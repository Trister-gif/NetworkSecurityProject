import os
import tempfile
import shutil
import subprocess
import json
from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import time 

# =================== 全局配置 ===================
# 保留您已验证的配置
CODEQL_PATH = r"D:\NetworkSecurity\codeql\codeql.exe"
RESULT_DIR = r"D:\NetworkSecurity\project\results"

# 删除所有Java环境变量设置！系统PATH已经配置好了
USER_HOME = os.path.expanduser("~")
CODEQL_REPO = os.path.join(USER_HOME, ".codeql", "packages")

# Java 查询套件
JAVA_QUERIES_PATH = os.path.join(CODEQL_REPO, "codeql", "java-queries", "1.8.2")
JAVA_SECURITY_SUITE = os.path.join(JAVA_QUERIES_PATH, "codeql-suites", "java-security-and-quality.qls")

# Python 1.6.6 版本（无 bug 版本）
PYTHON_QUERIES_166_PATH = r"D:\tmp\python-old\codeql\python-queries\1.6.6"
PYTHON_SECURITY_SUITE_166 = os.path.join(PYTHON_QUERIES_166_PATH, "codeql-suites", "python-security-and-quality.qls")

os.makedirs(RESULT_DIR, exist_ok=True)

# Flask
app = Flask(__name__, template_folder="templates")
CORS(app)

# =================== 工具函数 ===================
def run_command(cmd, cwd=None, env=None):
    try:
        print(f"[CMD] {cmd}")
        proc = subprocess.run(
            cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=True, text=True, encoding="utf-8", errors="ignore", timeout=300,
            env=env or os.environ.copy()
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -2, "", "命令执行超时"
    except Exception as e:
        return -1, "", str(e)

def detect_language(file_list):
    """整合同学改进的多语言检测"""
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

def has_maven_project(root):
    return os.path.exists(os.path.join(root, "pom.xml"))

def get_build_command(src_dir, lang, env):
    # ① 完整 Maven 项目
    if lang == "java" and has_maven_project(src_dir):
        return "mvn clean compile -DskipTests -Dmaven.test.skip=true"
    # ② 单文件/普通目录
    if lang == "java":
        files = []
        for root, _, fs in os.walk(src_dir):
            for f in fs:
                if f.endswith(".java"):
                    files.append(os.path.relpath(os.path.join(root, f), src_dir))
        return f'javac -encoding UTF-8 {" ".join(files)}' if files else "echo No Java"
    return "echo No build needed"

def get_query_suite(lang):
    if lang == "java":
        if os.path.exists(JAVA_SECURITY_SUITE):
            return JAVA_SECURITY_SUITE
        suite_dir = os.path.join(JAVA_QUERIES_PATH, "codeql-suites")
        if os.path.isdir(suite_dir):
            for f in os.listdir(suite_dir):
                if f.endswith(".qls"):
                    return os.path.join(suite_dir, f)
        return "codeql/java-queries"

    if lang == "javascript":
        js = os.path.join(CODEQL_REPO, "codeql", "javascript-queries")
        if os.path.isdir(js):
            q = os.path.join(js, "codeql-suites", "javascript-security-and-quality.qls")
            return q if os.path.exists(q) else js
        return "codeql/javascript-queries"

    if lang == "python":
        if os.path.exists(PYTHON_SECURITY_SUITE_166):
            return PYTHON_SECURITY_SUITE_166
        if os.path.isdir(PYTHON_QUERIES_166_PATH):
            suite_dir = os.path.join(PYTHON_QUERIES_166_PATH, "codeql-suites")
            if os.path.isdir(suite_dir):
                for f in os.listdir(suite_dir):
                    if f.endswith(".qls"):
                        return os.path.join(suite_dir, f)
            return PYTHON_QUERIES_166_PATH
        py = os.path.join(CODEQL_REPO, "codeql", "python-queries")
        if os.path.isdir(py):
            q = os.path.join(py, "codeql-suites", "python-code-scanning.qls")
            return q if os.path.exists(q) else py
        return "codeql/python-queries:codeql-suites/python-code-scanning.qls"

    if lang in ["cpp", "c"]:
        cpp = os.path.join(CODEQL_REPO, "codeql", "cpp-queries")
        if os.path.isdir(cpp):
            q = os.path.join(cpp, "codeql-suites", "cpp-security-and-quality.qls")
            return q if os.path.exists(q) else cpp
        return "codeql/cpp-queries"

    if lang == "csharp":
        cs = os.path.join(CODEQL_REPO, "codeql", "csharp-queries")
        if os.path.isdir(cs):
            q = os.path.join(cs, "codeql-suites", "csharp-security-and-quality.qls")
            return q if os.path.exists(q) else cs
        return "codeql/csharp-queries"

    return f"codeql/{lang}-queries"

def run_codeql_analysis(src_dir, lang):
    db_dir = os.path.join(src_dir, "codeql_db")

    # 重要：直接使用系统环境，不修改任何Java设置！
    env = os.environ.copy()

    build_cmd = get_build_command(src_dir, lang, env)

    # 简化命令，不使用任何Java相关参数
    base_args = f'"{CODEQL_PATH}" database create "{db_dir}" --language={lang} --source-root="{src_dir}" --overwrite'

    # 第一次：带构建
    if lang not in ["python", "javascript"]:
        cmd_create = base_args + f' --command="{build_cmd}"'
    else:
        cmd_create = base_args

    code, out, err = run_command(cmd_create, env=env)
    if code != 0:
        # fallback：不带构建命令
        cmd_create = base_args
        code, out, err = run_command(cmd_create, env=env)
        if code != 0:
            raise Exception(f"数据库创建失败:\nSTDOUT:{out}\nSTDERR:{err}")

    # 分析部分
    result_path = os.path.join(RESULT_DIR, f"result_{os.path.basename(src_dir)}_{lang}.sarif")
    query = get_query_suite(lang)
    if os.path.exists(query) and query.endswith(".qls"):
        cmd_analyze = f'"{CODEQL_PATH}" database analyze "{db_dir}" --format=sarif-latest --output="{result_path}" "{query}"'
    elif os.path.isdir(query):
        cmd_analyze = f'"{CODEQL_PATH}" database analyze "{db_dir}" --format=sarif-latest --output="{result_path}" "{query}"'
    else:
        cmd_analyze = f'"{CODEQL_PATH}" database analyze "{db_dir}" --format=sarif-latest --output="{result_path}" {query}'

    code, out, err = run_command(cmd_analyze, env=env)
    if code != 0:
        raise Exception(f"分析失败:\nSTDOUT:{out}\nSTDERR:{err}")

    if not os.path.exists(result_path):
        empty = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}]}
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(empty, f, ensure_ascii=False, indent=2)
    return result_path

def parse_sarif(sarif_file):
    """使用同学修复前端兼容性的版本"""
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

                level = r.get("level", "warning")
                
                # 修复前端兼容性 - 使用 "level" 而不是 "severity"
                results.append({
                    "rule": rule_id,
                    "level": level,  # 关键修复：对应前端 index.html 的 r.level
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
            return jsonify({"message": "未上传文件", "status": "error"}), 400
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"message": "未选择文件", "status": "error"}), 400

        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src")
            os.makedirs(src, exist_ok=True)
            fp = os.path.join(src, file.filename)
            file.save(fp)

            if file.filename.lower().endswith((".zip", ".tar", ".gz")):
                try:
                    shutil.unpack_archive(fp, src)
                    os.remove(fp)
                except Exception as e:
                    print("[WARN] 解压失败:", e)

            file_list = []
            for root, _, fs in os.walk(src):
                for f in fs:
                    file_list.append(os.path.relpath(os.path.join(root, f), src))
            lang = detect_language(file_list)
            if not lang:
                return jsonify({"message": "无法识别语言", "status": "error"}), 400

            print(f"[INFO] 语言: {lang}")
            sarif_path = run_codeql_analysis(src, lang)
            table = parse_sarif(sarif_path)

            # 统计
            count = len(table)
            msg = f"分析完成，发现 {count} 个问题" if count > 0 else "分析完成，未发现明显问题"

            return jsonify({
                "message": msg,
                "status": "ok",
                "language": lang,
                "results": table,
                "sarif_file": os.path.basename(sarif_path)
            })
    except Exception as e:
        print("[ERROR]", e)
        return jsonify({"message": str(e), "status": "error"}), 500

@app.route("/results/<path:filename>")
def download(filename):
    return send_from_directory(RESULT_DIR, filename, as_attachment=True)

@app.route("/api/history")
def get_history():
    """获取历史报告列表"""
    reports = []
    if not os.path.exists(RESULT_DIR):
        return jsonify(reports)
    
    # 按修改时间倒序排列 (最新的在最前)
    files = sorted(os.listdir(RESULT_DIR), key=lambda x: os.path.getmtime(os.path.join(RESULT_DIR, x)), reverse=True)
    
    for f in files:
        if f.endswith(".sarif"):
            path = os.path.join(RESULT_DIR, f)
            # 尝试从文件名解析信息: result_项目名_语言.sarif
            try:
                parts = f.replace(".sarif", "").split("_")
                # parts[0]="result", parts[1]=name, parts[2]=lang
                if len(parts) >= 3:
                    name = parts[1]
                    lang = parts[2]
                    # 使用文件修改时间作为日期
                    mtime = os.path.getmtime(path)
                    date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
                else:
                    name = f
                    lang = "-"
                    date_str = "Unknown"
            except:
                date_str = "Unknown"
                name = f
                lang = "-"
            
            # 文件大小
            size = os.path.getsize(path) / 1024 # KB
            
            reports.append({
                "filename": f,
                "project": name,
                "date": date_str,
                "language": lang,
                "size": f"{size:.1f} KB"
            })
    return jsonify(reports)

@app.route("/api/report_detail/<path:filename>")
def get_report_detail(filename):
    """读取并解析特定报告"""
    try:
        path = os.path.join(RESULT_DIR, filename)
        if not os.path.exists(path):
            return jsonify({"error": "File not found"}), 404
        
        # 复用之前的解析函数
        results = parse_sarif(path)
        return jsonify({
            "status": "ok", 
            "filename": filename,
            "results": results,
            "count": len(results)
        })
    except Exception as e:
           return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/stats")
def get_dashboard_stats():
    """获取统计信息"""
    stats = {
        "total_scans": 0,
        "total_vulns": 0,
        "severity_dist": {"error": 0, "warning": 0, "note": 0},
        "top_vulns": {} # {"rule_id": count}
    }
    
    if not os.path.exists(RESULT_DIR):
        return jsonify(stats)
    
    files = [f for f in os.listdir(RESULT_DIR) if f.endswith(".sarif")]
    stats["total_scans"] = len(files)
    
    for f in files:
        path = os.path.join(RESULT_DIR, f)
        try:
            results = parse_sarif(path)
            # 跳过空结果
            if not results:
                continue
                
            stats["total_vulns"] += len(results)
            
            for r in results:
                # 统计严重性
                level = r.get("level", "warning").lower()
                if "error" in level: stats["severity_dist"]["error"] += 1
                elif "warn" in level: stats["severity_dist"]["warning"] += 1
                else: stats["severity_dist"]["note"] += 1
                
                # 统计漏洞类型
                rule_name = r.get("rule", "unknown").split("/")[-1]
                stats["top_vulns"][rule_name] = stats["top_vulns"].get(rule_name, 0) + 1
                
        except Exception:
            pass # 忽略损坏的文件

    # 整理 Top 5 漏洞数据用于前端柱状图
    sorted_vulns = sorted(stats["top_vulns"].items(), key=lambda x: x[1], reverse=True)[:5]
    stats["top_vulns_chart"] = {
        "labels": [item[0] for item in sorted_vulns],
        "data": [item[1] for item in sorted_vulns]
    }
    del stats["top_vulns"] # 删除原始大字典节省流量
    
    return jsonify(stats)

if __name__ == "__main__":
    print("[INFO] CodeQL:", CODEQL_PATH)
    app.run(host="0.0.0.0", port=5000, debug=True)