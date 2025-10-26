import os
import tempfile
import shutil
import subprocess
import json
from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS

# =================== 全局配置 ===================
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
    exts = {}
    for f in file_list:
        ext = os.path.splitext(f)[1].lower()
        if ext == ".java":
            exts["java"] = exts.get("java", 0) + 1
        elif ext == ".py":
            exts["python"] = exts.get("python", 0) + 1
        elif ext in [".cpp", ".cc", ".cxx", ".c++"]:
            exts["cpp"] = exts.get("cpp", 0) + 1
        elif ext in [".c", ".h"]:
            exts["c"] = exts.get("c", 0) + 1
        elif ext in [".js", ".jsx", ".ts", ".tsx"]:
            exts["javascript"] = exts.get("javascript", 0) + 1
        elif ext == ".cs":
            exts["csharp"] = exts.get("csharp", 0) + 1
    return max(exts.items(), key=lambda x: x[1])[0] if exts else None

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
    try:
        with open(sarif_file, encoding="utf-8") as f:
            data = json.load(f)
        results = []
        for run in data.get("runs", []):
            for r in run.get("results", []):
                rule = r.get("ruleId", "unknown")
                msg = r.get("message", {}).get("text", "")
                level = r.get("level", "warning")
                loc, line = "unknown", "-"
                for l in r.get("locations", []):
                    phys = l.get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    start = phys.get("region", {}).get("startLine", "")
                    if uri:
                        loc, line = uri, str(start) if start else "-"
                        break
                severity = {"error": "error", "warning": "warning", "note": "info"}.get(level, "warning")
                results.append({"rule": rule, "severity": severity, "file": loc, "line": line, "message": msg})
        return results if results else [{"rule": "完成", "severity": "info", "file": "-", "line": "-", "message": "未发现问题"}]
    except Exception as e:
        return [{"rule": "解析错误", "severity": "error", "file": "-", "line": "-", "message": str(e)}]

# =================== 路由 ===================
@app.route("/")
def index():
    return render_template("index.html")

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

            return jsonify({
                "message": "分析完成",
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

if __name__ == "__main__":
    print("[INFO] CodeQL:", CODEQL_PATH)
    app.run(host="0.0.0.0", port=5000, debug=True)