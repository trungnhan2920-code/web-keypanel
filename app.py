"""BRMods Key Panel v2 — web quản lý key BRMods (time thật) với auth tài khoản.

Auth:
  - users table (username, PBKDF2-SHA256 password hash, role)
  - login username+password -> session token (random, DB, hết hạn 7 ngày)
  - cookie panel_session = token (không lộ password)
  - admin đầu tiên: env ADMIN_USERNAME / ADMIN_PASSWORD (mặc định admin/admin123)
Endpoint:
  POST /api/login {username,password}      -> set cookie
  POST /api/logout
  GET  /api/me
  POST /api/register {username,password}   (admin)
  POST /api/change-password {old,new}      (self)
  Key (cần auth):
  GET  /api/stats | /api/keys | /api/export
  POST /api/create {name,pack,note} | /api/grant {name,pack}
  POST /api/revoke | /api/reset | /api/note
  POST /api/import {records:[...]}
  Public (cho auth-swap cloud):
  GET  /api/verify?key=...
Deploy: gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4
Local : python app.py (127.0.0.1:8080)
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import traceback

import key_store as ks

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "index.html")
DB = ks.DB  # same sqlite DB file as keys (data/brmod_keys.db or KEYSTORE_DB)

COOKIE = "panel_session"
SESSION_DAYS = 7
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")


# ---------------- users / sessions ----------------
def _db():
    c = sqlite3.connect(DB, timeout=10)
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, pass_hash TEXT NOT NULL, role TEXT DEFAULT 'admin',
        created_at INTEGER NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY, username TEXT NOT NULL, created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL)""")
    c.commit()
    return c


def _ensure_admin():
    c = _db()
    if not c.execute("SELECT username FROM users LIMIT 1").fetchone():
        # INSERT OR IGNORE: an toàn khi nhiều worker boot cùng lúc (gunicorn)
        c.execute("INSERT OR IGNORE INTO users(username,pass_hash,role,created_at) VALUES(?,?,?,?)",
                  (ADMIN_USERNAME, _hash(ADMIN_PASSWORD), "admin", int(time.time())))
        c.commit()
    c.close()


def _hash(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 100_000).hex()
    return "%s$%s" % (salt, dk)


def _verify(pw, stored):
    try:
        salt, dk = stored.split("$")
    except Exception:
        return False
    return hmac.compare_digest(_hash(pw, salt), stored)


def _create_session(username):
    token = secrets.token_hex(32)
    now = int(time.time())
    c = _db()
    c.execute("INSERT INTO sessions(token,username,created_at,expires_at) VALUES(?,?,?,?)",
              (token, username, now, now + SESSION_DAYS * 86400))
    c.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    c.commit()
    c.close()
    return token


def _user_by_session(token):
    if not token:
        return None
    c = _db()
    row = c.execute("""SELECT u.username, u.role FROM sessions s
                       JOIN users u ON u.username = s.username
                       WHERE s.token=? AND s.expires_at > ?""",
                    (token, int(time.time()))).fetchone()
    c.close()
    return {"username": row[0], "role": row[1]} if row else None


def _user(username):
    c = _db()
    row = c.execute("SELECT username, pass_hash, role FROM users WHERE username=?", (username,)).fetchone()
    c.close()
    return {"username": row[0], "pass_hash": row[1], "role": row[2]} if row else None


def _logout(token):
    if not token:
        return
    c = _db()
    c.execute("DELETE FROM sessions WHERE token=?", (token,))
    c.commit()
    c.close()


def fail(msg):
    return {"ok": False, "error": msg}


def _json(obj):
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def _resp(start_response, code, body_bytes, ctype="application/json; charset=utf-8", extra=None):
    headers = [("Content-Type", ctype), ("Content-Length", str(len(body_bytes)))]
    if extra:
        headers += extra
    start_response(code, headers)
    return [body_bytes]


class WSGIApp:
    def __call__(self, environ, start_response):
        try:
            return self._dispatch(environ, start_response)
        except Exception:
            tb = traceback.format_exc()
            try:
                open(os.path.join(HERE, "data", "error.log"), "a", encoding="utf-8").write(tb + "\n")
            except Exception:
                pass
            out = _json(fail("server error"))
            return _resp(start_response, "500 Internal Server Error", out)

    def _dispatch(self, environ, start_response):
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET")
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except Exception:
            length = 0
        body = environ.get("wsgi.input").read(length) if length else b""
        cookie = environ.get("HTTP_COOKIE") or ""
        token = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith(COOKIE + "="):
                token = part[len(COOKIE) + 1:]
                break

        if path == "/":
            if os.path.exists(INDEX):
                data = open(INDEX, "rb").read()
                return _resp(start_response, "200 OK", data, "text/html; charset=utf-8",
                             [("Cache-Control", "no-store")])
            return _resp(start_response, "404 Not Found", b"index.html missing", "text/plain")

        if not path.startswith("/api/"):
            return _resp(start_response, "404 Not Found", b"not found", "text/plain")

        # ---------- public: verify (auth-swap cloud) ----------
        if path == "/api/verify" and method == "GET":
            from urllib.parse import parse_qs
            qs = parse_qs(environ.get("QUERY_STRING", "") or "")
            name = (qs.get("key") or qs.get("name") or [""])[0].strip()
            if not name:
                return _resp(start_response, "200 OK", _json(fail("missing key")))
            row = ks.get(name)
            if not row:
                return _resp(start_response, "200 OK",
                             _json({"ok": False, "valid": False, "name": name, "message": "key not found"}))
            now = int(time.time())
            ok = row["status"] == "active" and (row["expires_at"] >= ks.LIFETIME_UNIX or row["expires_at"] > now)
            if ok:
                msg = "lifetime" if row["expires_at"] >= ks.LIFETIME_UNIX else (
                    "ok until %s" % time.strftime("%Y-%m-%d %H:%M:%S",
                                                  time.localtime(row["expires_at"])))
            else:
                msg = "status=%s" % row["status"] if row["status"] != "active" else "expired"
            return _resp(start_response, "200 OK", _json({
                "ok": ok, "valid": ok, "name": row["name"], "status": row["status"],
                "pack": row["pack"], "expires_at": row["expires_at"], "hwid": row["hwid"],
                "message": msg,
            }))

        # ---------- public auth ----------
        if path == "/api/login" and method == "POST":
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                data = {}
            u = _user(str(data.get("username", "")))
            if u and _verify(str(data.get("password", "")), u["pass_hash"]):
                token = _create_session(u["username"])
                return _resp(start_response, "200 OK", _json({"username": u["username"], "role": u["role"]}),
                             extra=[("Set-Cookie", "%s=%s; Path=/; HttpOnly; Max-Age=%d"
                                     % (COOKIE, token, SESSION_DAYS * 86400))])
            return _resp(start_response, "401 Unauthorized", _json(fail("sai tài khoản/mật khẩu")))
        if path == "/api/logout" and method == "POST":
            _logout(token)
            return _resp(start_response, "200 OK", b"{}",
                         extra=[("Set-Cookie", "%s=; Path=/; Max-Age=0" % COOKIE)])

        # ---------- authenticated ----------
        me = _user_by_session(token)
        if not me:
            return _resp(start_response, "401 Unauthorized", _json(fail("unauthorized")))

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            data = {}

        if path == "/api/me":
            return _resp(start_response, "200 OK", _json(me))

        # v2: mọi endpoint key đều cần admin
        is_admin = me["role"] == "admin"
        if not is_admin:
            return _resp(start_response, "403 Forbidden", _json(fail("cần tài khoản admin")))

        if path == "/api/register" and method == "POST":
            uname = str(data.get("username", "")).strip()
            pw = str(data.get("password", ""))
            if not uname or len(pw) < 6:
                return _resp(start_response, "400 Bad Request", _json(fail("username rỗng / password >=6 ký tự")))
            c = _db()
            cur = c.execute("SELECT username FROM users WHERE username=?", (uname,))
            if cur.fetchone():
                c.close()
                return _resp(start_response, "400 Bad Request", _json(fail("username đã tồn tại")))
            c.execute("INSERT INTO users(username,pass_hash,role,created_at) VALUES(?,?,?,?)",
                      (uname, _hash(pw), "admin", int(time.time())))
            c.commit()
            c.close()
            return _resp(start_response, "200 OK", _json({"ok": True, "username": uname}))

        if path == "/api/change-password" and method == "POST":
            u = _user(me["username"])
            if not _verify(str(data.get("old", "")), u["pass_hash"]):
                return _resp(start_response, "400 Bad Request", _json(fail("mật khẩu cũ sai")))
            newpw = str(data.get("new", ""))
            if len(newpw) < 6:
                return _resp(start_response, "400 Bad Request", _json(fail("password mới >=6 ký tự")))
            c = _db()
            c.execute("UPDATE users SET pass_hash=? WHERE username=?", (_hash(newpw), me["username"]))
            c.commit()
            c.close()
            return _resp(start_response, "200 OK", _json({"ok": True}))

        # ---------- key APIs ----------
        if path == "/api/stats":
            return _resp(start_response, "200 OK", _json(ks.stats()))
        if path == "/api/keys":
            return _resp(start_response, "200 OK", _json(ks.list_keys()))
        if path == "/api/export":
            return _resp(start_response, "200 OK", _json(ks.export_json()),
                         extra=[("Content-Disposition", 'attachment; filename="brmod_keys_export.json"')])
        if path == "/api/create" and method == "POST":
            ok, msg, row = ks.create(str(data.get("name", "")), int(data.get("pack", 0) or 0),
                                     str(data.get("note") or ""))
            return _resp(start_response, "200 OK", _json(row if ok else fail(msg)))
        if path == "/api/grant" and method == "POST":
            ok, msg, row = ks.grant(str(data.get("name", "")), int(data.get("pack", 0) or 0))
            return _resp(start_response, "200 OK", _json(row if ok else fail(msg)))
        if path == "/api/revoke" and method == "POST":
            ok, msg, row = ks.set_status(str(data.get("name", "")), "revoked")
            return _resp(start_response, "200 OK", _json(row if ok else fail(msg)))
        if path == "/api/reset" and method == "POST":
            ok, msg, row = ks.reset(str(data.get("name", "")))
            return _resp(start_response, "200 OK", _json(row if ok else fail(msg)))
        if path == "/api/note" and method == "POST":
            ok, msg, row = ks.set_note(str(data.get("name", "")), str(data.get("note") or ""))
            return _resp(start_response, "200 OK", _json(row if ok else fail(msg)))
        if path == "/api/import" and method == "POST":
            records = data.get("records", [])
            if not isinstance(records, list):
                return _resp(start_response, "400 Bad Request", _json(fail("records phải là mảng JSON")))
            out = ks.import_records(records)
            return _resp(start_response, "200 OK", _json(out))

        return _resp(start_response, "404 Not Found", _json(fail("not found")))


app = WSGIApp()


def main():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _run(self):
            env = {
                "PATH_INFO": self.path.split("?")[0],
                "QUERY_STRING": self.path.split("?", 1)[1] if "?" in self.path else "",
                "REQUEST_METHOD": self.command,
                "CONTENT_LENGTH": self.headers.get("Content-Length") or "0",
                "HTTP_COOKIE": self.headers.get("Cookie") or "",
            }

            class FakeInput:
                def __init__(self, rf):
                    self.rf = rf

                def read(self, n):
                    return self.rf.read(n)

            env["wsgi.input"] = FakeInput(self.rfile)

            def start_response(status, headers):
                code = int(status.split(" ")[0])
                self.send_response(code)
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()

            for chunk in app(env, start_response):
                if isinstance(chunk, bytes):
                    self.wfile.write(chunk)

        def do_GET(self):
            self._run()

        def do_POST(self):
            self._run()

    _ensure_admin()
    os.makedirs(os.path.join(HERE, "data"), exist_ok=True)
    port = int(os.environ.get("PORT") or os.environ.get("PANEL_PORT", 8080))
    bind = os.environ.get("PANEL_BIND", "127.0.0.1")
    srv = ThreadingHTTPServer((bind, port), H)
    print("[%s] BRMods Key Panel v2 on http://%s:%d — admin '%s'"
          % (time.strftime("%H:%M:%S"), bind, port, ADMIN_USERNAME))
    srv.serve_forever()


# gunicorn workers: ensure admin + data/ dir exist
try:
    _ensure_admin()
    os.makedirs(os.path.join(HERE, "data"), exist_ok=True)
except Exception:
    pass

if __name__ == "__main__":
    main()