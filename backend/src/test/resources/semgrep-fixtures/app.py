import os, pickle, subprocess, sqlite3, ssl, yaml
import requests
from flask import Flask, render_template_string
from flask_cors import CORS
from django.views.decorators.csrf import csrf_exempt
from markupsafe import Markup

app = Flask(__name__)
# codelens-expect: PERMISSIVE_CORS
CORS(app)
CORS(app, origins=["https://devert.in"])


def find_user(conn, user_id, name):
    cur = conn.cursor()
    # codelens-expect: SQL_INJECTION
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # codelens-expect: SQL_INJECTION
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # codelens-expect: SQL_INJECTION
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(query)
    label = "processing " + name
    cur.execute("SELECT * FROM jobs WHERE label = ?", (label,))
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    cur.execute("SELECT count(*) FROM users")
    return cur.fetchall()


def run(host, path):
    # codelens-expect: COMMAND_INJECTION
    os.system("ping -c 1 " + host)
    # codelens-expect: COMMAND_INJECTION
    subprocess.run(f"ls {path}", shell=True)
    subprocess.run(["ls", path])
    subprocess.run("ls -la", shell=True)
    os.system("clear")


def load(blob, text, expr):
    # codelens-expect: INSECURE_DESERIALIZATION
    obj = pickle.loads(blob)
    # codelens-expect: INSECURE_DESERIALIZATION
    cfg = yaml.load(text)
    safe = yaml.load(text, Loader=yaml.SafeLoader)
    also_safe = yaml.safe_load(text)
    # codelens-expect: CODE_INJECTION
    value = eval(expr)
    constant = eval("1 + 2")
    return obj, cfg, safe, also_safe, value, constant


def fetch(url):
    # codelens-expect: TLS_VERIFY_DISABLED
    r = requests.get(url, verify=False)
    ok = requests.get(url, verify="/etc/ca.pem")
    # codelens-expect: TLS_VERIFY_DISABLED
    ctx = ssl._create_unverified_context()
    return r, ok, ctx


def page(name):
    # codelens-expect: UNSAFE_HTML
    return render_template_string("<h1>Hi " + name + "</h1>")


def banner(msg):
    # codelens-expect: UNSAFE_HTML
    return Markup(msg)


def fixed():
    return Markup("<b>static</b>")


# codelens-expect: CSRF_DISABLED
@csrf_exempt
def webhook(request):
    return None


def risky():
    # codelens-expect: SWALLOWED_EXCEPTION
    try:
        do_work()
    except Exception:
        pass
    try:
        import ujson as json
    except ImportError:
        pass


# codelens-expect: MUTABLE_DEFAULT_ARGUMENT
def add_item(item, bucket=[]):
    bucket.append(item)
    return bucket


def add_item_ok(item, bucket=None):
    bucket = bucket or []
    return bucket


def check(status, count):
    # codelens-expect: LITERAL_IDENTITY_COMPARISON
    if status is "done":
        return True
    # codelens-expect: LITERAL_IDENTITY_COMPARISON
    if count is not 0:
        return False
    if status is None or count is True:
        return None


if __name__ == "__main__":
    # codelens-expect: DEBUG_MODE
    app.run(host="0.0.0.0", debug=True)
    app.run(debug=False)
