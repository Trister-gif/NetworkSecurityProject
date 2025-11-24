import os
import tempfile
import shutil
import subprocess
import json
from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS

# =================== 全局配置 (macOS/Linux 适配版) ===================

# 1. 尝试从系统路径获取 codeql，如果获取不到则需要手动指定
CODEQL_BIN = shutil.which("codeql")
if not CODEQL_BIN:
    # 如果 brew install codeql 后找不到，可以在这里填入绝对路径
    # 例如: CODEQL_BIN = "/usr/local/bin/codeql"
    print("[警告] 未在 PATH 中找到 codeql，请确保已安装！")
    CODEQL_BIN = "codeql" 

# 2. 结果存储在当前目录下的 results 文件夹
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_DIR = os.path.join(BASE_DIR, "results")

# 3. CodeQL 查询库路径 (适配刚才 git clone 的位置)
# 假设你把 codeql repo 克隆到了 ~/codeql-repo/codeql
USER_HOME = os.path.expanduser("~")
CODEQL_REPO_PATH = os.path.join(USER_HOME, "codeql-repo", "codeql")

os.makedirs(RESULT_DIR, exist_ok=True)

app = Flask(__name__, template_folder="templates")
CORS(app)

# =================== 工具函数 ===================
def run_command(cmd, cwd=None, env=None):
    try:
        print(f"[CMD] {cmd}")
        # macOS/Linux 下 shell=True 通常没问题，但要注意路径转义
        proc = subprocess.run(
            cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=True, text=True, errors="ignore", timeout=600, # 增加超时时间
            env=env or os.environ.copy()
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -2, "", "命令执行超时 (Timeout)"
    except Exception as e:
        return -1, "", str(e)

def detect_language(file_list):
    exts = {}
    for f in file_list:
        ext = os.path.splitext(f)[1].lower()
        mapping = {
            ".java": "java",
            ".py": "python",
            ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
            ".c": "cpp", ".cpp": "cpp", ".h": "cpp", ".cc": "cpp",
            ".cs": "csharp",
            ".go": "go",
            ".rb": "ruby"
        }
        if ext in mapping:
            lang = mapping[ext]
            exts[lang] = exts.get(lang, 0) + 1
    
    if not exts: 
        return None
    return max(exts.items(), key=lambda x: x[1])[0]

def get_build_command(src_dir, lang):
    """
    CodeQL 对编译型语言(Java/C++)需要构建命令。
    """
    if lang == "java":
        if os.path.exists(os.path.join(src_dir, "pom.xml")):
            # macOS 下 mvn 命令通常在 PATH 中
            return "mvn clean compile -DskipTests"
        if os.path.exists(os.path.join(src_dir, "gradlew")):
            return "./gradlew clean assemble"
        # 简单 Java 项目尝试 javac
        return "javac -cp . *.java" # 这是一个非常简化的 fallback
    return None # Python/JS 不需要构建命令

def get_query_suite(lang):
    """
    获取查询套件路径。
    优先尝试构建标准路径，如果不存在则返回简短名称让 CLI 自己去解析(依赖 CodeQL Packs)
    """
    # 尝试在我们 clone 的仓库里找
    if os.path.exists(CODEQL_REPO_PATH):
        # 典型的路径结构: ~/codeql-repo/codeql/python/ql/src/codeql-suites/python-security-and-quality.qls
        # 注意：不同版本的 github/codeql 目录结构可能微调，这里使用一种通用的查找策略
        
        # 常见路径变体
        candidates = [
            os.path.join(CODEQL_REPO_PATH, lang, "ql", "src", "codeql-suites", f"{lang}-security-and-quality.qls"),
            os.path.join(CODEQL_REPO_PATH, lang, "ql", "src", "codeql-suites", f"{lang}-code-scanning.qls"),
        ]
        
        for path in candidates:
            if os.path.exists(path):
                return f'"{path}"'

    # 如果找不到本地文件，直接返回标准套件名
    # CodeQL CLI 会尝试从缓存或 internet 下载 packs (需要联网)
    return f"{lang}-security-and-quality.qls" 

def run_codeql_analysis(src_dir, lang):
    db_dir = os.path.join(src_dir, "codeql_db")
    env = os.environ.copy()
    
    # 1. 创建数据库
    # --source-root 必须是绝对路径
    src_dir_abs = os.path.abspath(src_dir)
    
    cmd_create_parts = [
        f'"{CODEQL_BIN}"', "database", "create", f'"{db_dir}"',
        f'--language={lang}',
        f'--source-root="{src_dir_abs}"',
        "--overwrite"
    ]
    
    build_cmd = get_build_command(src_dir, lang)
    if build_cmd:
        # 如果需要构建，加入 command 参数
        cmd_create_parts.append(f'--command="{build_cmd}"')
    
    cmd_create = " ".join(cmd_create_parts)
    
    print(f"[INFO] Creating DB for {lang}...")
    code, out, err = run_command(cmd_create, env=env)
    
    # 如果构建失败且是 Java/C++，这通常是致命错误。
    # 但如果是 Python/JS，有时候不需要 build command 也能跑
    if code != 0:
        print(f"[WARN] DB Create failed: {err}")
        # 尝试不带 build command (针对解释型语言或自动构建)
        if not build_cmd:
            raise Exception(f"数据库创建失败: {err}\n{out}")
            
    # 2. 分析数据库
    result_filename = f"result_{os.path.basename(src_dir)}_{lang}.sarif"
    result_path = os.path.join(RESULT_DIR, result_filename)
    
    query_suite = get_query_suite(lang)
    print(f"[INFO] Using Query Suite: {query_suite}")

    # --download 允许 CLI 自动下载缺少的查询包
    cmd_analyze = f'"{CODEQL_BIN}" database analyze "{db_dir}" "{query_suite}" --format=sarif-latest --output="{result_path}" --download'
    
    print(f"[INFO] Analyzing...")
    code, out, err = run_command(cmd_analyze, env=env)
    if code != 0:
         # 尝试降级使用 code-scanning 套件
        print(f"[WARN] Analyze failed, retrying with default suite. Error: {err}")
        cmd_analyze = f'"{CODEQL_BIN}" database analyze "{db_dir}" {lang}-code-scanning.qls --format=sarif-latest --output="{result_path}" --download'
        code, out, err = run_command(cmd_analyze, env=env)
        if code != 0:
            raise Exception(f"分析失败: {err}\n{out}")

    if not os.path.exists(result_path):
        # 生成空文件防止报错
        with open(result_path, "w") as f:
            json.dump({"runs": []}, f)
            
    return result_path

def parse_sarif(sarif_file):
    try:
        with open(sarif_file, encoding="utf-8") as f:
            data = json.load(f)
        results = []
        for run in data.get("runs", []):
            for r in run.get("results", []):
                rule_id = r.get("ruleId", "unknown")
                msg = r.get("message", {}).get("text", "")
                
                # 获取位置
                loc_display = "-"
                line_display = "-"
                locations = r.get("locations", [])
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    start_line = phys.get("region", {}).get("startLine", "")
                    if uri:
                        loc_display = uri
                        line_display = str(start_line)

                # 获取严重性
                # CodeQL SARIF 结构通常在 properties 里，或者根据 ruleId 推断
                # 这里简单处理 level
                level = r.get("level", "warning") # note, warning, error
                
                # 为了修复前端 bug，我们直接把 key 设为 level 或者 severity，前端用哪个就给哪个
                # 你的前端 index.html 用的是 r.level，所以这里 key 改为 level
                results.append({
                    "rule": rule_id,
                    "level": level,  # 修复: 对应前端 index.html 的 r.level
                    "file": loc_display,
                    "line": line_display,
                    "message": msg
                })
        return results if results else []
    except Exception as e:
        print(f"[ERROR] Parse SARIF: {e}")
        return []

# =================== 路由 ===================
@app.route("/")
def index():
    """首页 - 代码审计"""
    return render_template("index.html")

@app.route("/generator")
def generator():
    """QL 规则生成器页面"""
    return render_template("generator.html")

@app.route("/reports")
def reports():
    """审计报告历史页面"""
    return render_template("reports.html")

@app.route("/profile")
def profile():
    """个人中心页面"""
    return render_template("profile.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        if "file" not in request.files:
            return jsonify({"message": "No file uploaded", "status": "error"}), 400
        file = request.files["file"]
        if not file.filename:
            return jsonify({"message": "No filename", "status": "error"}), 400

        # 使用临时目录处理
        with tempfile.TemporaryDirectory() as tmp_dir:
            src_dir = os.path.join(tmp_dir, "src")
            os.makedirs(src_dir, exist_ok=True)
            
            # 保存上传的文件
            save_path = os.path.join(src_dir, file.filename)
            file.save(save_path)
            
            # 如果是压缩包则解压
            if file.filename.lower().endswith((".zip", ".tar", ".gz")):
                try:
                    shutil.unpack_archive(save_path, src_dir)
                    os.remove(save_path) # 删除压缩包，只留源码
                except Exception as e:
                    print(f"[WARN] Unpack failed: {e}")

            # 扁平化文件列表用于检测语言
            file_list = []
            for root, _, fs in os.walk(src_dir):
                for f in fs:
                    file_list.append(os.path.join(root, f))
            
            lang = detect_language(file_list)
            if not lang:
                return jsonify({"message": "Unsupported language or empty", "status": "error"}), 400

            print(f"[INFO] Detected Language: {lang}")
            
            # 运行分析
            sarif_path = run_codeql_analysis(src_dir, lang)
            
            # 解析结果
            table_data = parse_sarif(sarif_path)
            
            # 统计
            count = len(table_data)
            msg = f"分析完成，发现 {count} 个问题" if count > 0 else "分析完成，未发现明显问题"

            return jsonify({
                "message": msg,
                "status": "ok",
                "language": lang,
                "results": table_data,
                "sarif_file": os.path.basename(sarif_path)
            })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"message": str(e), "status": "error"}), 500

@app.route("/results/<path:filename>")
def download(filename):
    return send_from_directory(RESULT_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    print(f"[INFO] Server starting... CodeQL binary: {CODEQL_BIN}")
    app.run(host="0.0.0.0", port=1234, debug=True)