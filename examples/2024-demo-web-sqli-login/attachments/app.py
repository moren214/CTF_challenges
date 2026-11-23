"""示例题目附件：一个有 SQL 注入的登录框（仅用于演示知识库结构，勿部署）。"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)

BAD = (" ", "union", "select", "--")


def db():
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE users (name TEXT, pass TEXT)")
    con.execute("INSERT INTO users VALUES ('admin', '{{FLAG}}')")
    return con


@app.route("/login", methods=["POST"])
def login():
    name = request.form.get("username", "")
    pw = request.form.get("password", "")
    for token in BAD:
        if token in name:
            return "WAF", 403
    con = db()
    # 漏洞点：字符串拼接；过滤只挡了空格/union/select/--
    row = con.execute(
        f"SELECT name FROM users WHERE name='{name}' AND pass='{pw}'"
    ).fetchone()
    return ("欢迎 " + row[0]) if row else "登录失败", (200 if row else 401)


if __name__ == "__main__":
    app.run(port=5000)
