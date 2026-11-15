#!/usr/bin/env python3
# xapi: API auth (verifikasi WhatsApp) + database JSON lokal. Hanya stdlib, tanpa pip.
# Jalankan: python3 xapi.py run | python3 xapi.py config [set KUNCI NILAI] | python3 xapi.py users
import json, os, sys, re, time, hmac, hashlib, base64, secrets, threading, subprocess, urllib.request, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

CONF = os.environ.get("XAPI_CONF", "/etc/xapi/config.json")
DEF = {"host": "127.0.0.1", "port": 8787, "data_dir": "/var/lib/xapi", "cors": "*", "panel": True,
       "wa_provider": "console", "wa_token": "", "otp_ttl": 300, "session_hours": 48, "secret": "", "admin_key": "", "admin_user": "x", "admin_pass": "x"}
L = threading.Lock()
OTP, FAIL = {}, {}

def rj(p, d):
    try:
        with open(p) as f: return json.load(f)
    except Exception: return d

def wj(p, o):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p + ".tmp", "w") as f: json.dump(o, f, ensure_ascii=False, indent=1)
    os.replace(p + ".tmp", p)

def upd(p, fn, d):  # baca-ubah-tulis atomik
    with L:
        o = rj(p, d); r = fn(o); wj(p, o); return r

def conf():  # dibaca ulang tiap request: panel/cors/wa berlaku langsung tanpa restart
    c = {**DEF, **rj(CONF, {})}
    if not c["secret"] or not c["admin_key"]:
        c["secret"] = c["secret"] or secrets.token_hex(24)
        c["admin_key"] = c["admin_key"] or secrets.token_hex(8)
        wj(CONF, c); os.chmod(CONF, 0o600)
    return c

def norm(w):
    w = re.sub(r"\D", "", str(w or ""))
    w = "62" + w[1:] if w.startswith("0") else "62" + w if w.startswith("8") else w
    return w if re.fullmatch(r"628\d{7,11}", w) else ""

def hp(p, s=None):
    s = s or secrets.token_hex(8)
    return s + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), s.encode(), 150000).hex()

def cp(p, h): return hmac.compare_digest(hp(p, h.split("$")[0]), h)

def sign(b, c): return hmac.new(c["secret"].encode(), b.encode(), "sha256").hexdigest()

def mk(u, c, a=0):
    b = base64.urlsafe_b64encode(json.dumps({"u": u, "a": a, "e": int(time.time()) + int(c["session_hours"]) * 3600}).encode()).decode()
    return b + "." + sign(b, c)

def ck(t, c):
    try:
        b, s = t.split(".")
        d = json.loads(base64.urlsafe_b64decode(b))
        return d if hmac.compare_digest(s, sign(b, c)) and d["e"] > time.time() else None
    except Exception: return None

def throttle(k):
    n, t = FAIL.get(k, (0, 0))
    n = n + 1 if time.time() - t < 600 else 1
    FAIL[k] = (n, time.time()); return n > 8

def wa(to, msg, c):  # kirim WhatsApp: "fonnte" (HTTP API) atau "console" (cetak ke log, untuk uji)
    if c["wa_provider"] == "fonnte":
        req = urllib.request.Request("https://api.fonnte.com/send",
              urllib.parse.urlencode({"target": to, "message": msg}).encode(), {"Authorization": c["wa_token"]})
        if not json.loads(urllib.request.urlopen(req, timeout=15).read()).get("status"): raise RuntimeError("Fonnte menolak")
    else:
        print(f"[OTP -> {to}] {msg}", flush=True)

def send_code(key, to, c):  # return pesan error, atau None kalau sukses
    o = OTP.get(key)
    if o and time.time() - o["t"] < 60: return "Tunggu 60 detik sebelum kirim ulang kode."
    code = f"{secrets.randbelow(10**6):06d}"
    try: wa(to, f"Kode verifikasi Xozen: {code}\nBerlaku {c['otp_ttl'] // 60} menit. Jangan bagikan ke siapa pun.", c)
    except Exception as e:
        print("WA gagal:", e, flush=True); return "Gagal mengirim WhatsApp. Periksa wa_provider / wa_token di server."
    OTP[key] = {"c": code, "t": time.time(), "n": 0}

def chk(key, code, c):
    o = OTP.get(key)
    if not o or time.time() - o["t"] > c["otp_ttl"] or o["n"] >= 5: return False
    o["n"] += 1
    if hmac.compare_digest(o["c"], str(code).strip()): del OTP[key]; return True
    return False

def find(us, i):  # cari user lewat username atau nomor WA
    i = str(i).strip().lower(); n = norm(i)
    for k, v in us.items():
        if k == i or (n and v["wa"] == n): return k, v
    return None, None

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def cors(self):
        self.send_header("Access-Control-Allow-Origin", conf()["cors"])
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    def out(self, code, o):
        b = json.dumps(o, ensure_ascii=False).encode()
        self.send_response(code); self.cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_OPTIONS(self): self.send_response(204); self.cors(); self.end_headers()
    def route(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000: return self.out(413, {"error": "Data terlalu besar"})
            b = json.loads(self.rfile.read(n)) if n else {}
            if not isinstance(b, dict): raise ValueError
        except Exception: return self.out(400, {"error": "Body harus JSON object"})
        try: self.out(*self.api(conf(), self.command, urllib.parse.urlparse(self.path).path.strip("/").split("/"), b))
        except Exception as e:
            print("ERR", repr(e), flush=True); self.out(500, {"error": "Kesalahan server"})
    do_GET = do_POST = do_PUT = do_DELETE = route

    def api(self, c, m, p, b):
        uf = os.path.join(c["data_dir"], "users.json"); us = rj(uf, {})
        if p in ([""], ["health"]): return 200, {"ok": True, "app": "xapi"}

        if p[0] == "admin":  # panel admin: header X-Admin-Key, bisa dimatikan (panel=false)
            if not c["panel"]: return 403, {"error": "Panel dinonaktifkan"}
            if not self.is_admin(c): return 401, {"error": "Akses admin ditolak"}
            if m == "GET": return 200, [{"username": v["u"], "wa": v["wa"], "suspended": bool(v.get("s"))} for v in us.values()]
            if m == "DELETE" and len(p) == 3: upd(uf, lambda o: o.pop(p[2].lower(), None), {}); return 200, {"ok": True}
            if m == "POST" and len(p) == 4 and p[3] in ("suspend", "unsuspend"):
                k = p[2].lower()
                if k not in us: return 404, {"error": "Akun tidak ada"}
                upd(uf, lambda o: o[k].update(s=p[3] == "suspend") if p[3] == "suspend" else o[k].pop("s", None), {}); return 200, {"ok": True}
            return 404, {"error": "Tidak ada"}

        if p[:2] == ["api", "auth"] and len(p) == 3:
            a = p[2]
            if a == "code":
                pu = b.get("purpose"); w = norm(b.get("wa", ""))
                if pu == "reset":
                    _, v = find(us, b.get("id", ""))
                    if not v: return 200, {"ok": True}  # tidak membocorkan akun mana yang ada
                    w = v["wa"]
                else: return 400, {"error": "purpose harus reset"}
                e = send_code(pu + ":" + w, w, c)
                return (429, {"error": e}) if e else (200, {"ok": True})
            if a == "register":
                u = str(b.get("username", "")).strip().lower(); w = norm(b.get("wa", "")); pw = str(b.get("password", ""))
                if not re.fullmatch(r"[a-z][a-z0-9_.]{2,19}", u): return 400, {"error": "Username 3-20 karakter, diawali huruf (a-z, 0-9, _ .)"}
                if not w or len(pw) < 6: return 400, {"error": "Nomor WhatsApp tidak valid atau kata sandi kurang dari 6 karakter"}
                if u in us or u == c["admin_user"].lower(): return 409, {"error": "Username sudah dipakai"}
                def f(o):
                    if u in o or any(v["wa"] == w for v in o.values()): return False
                    o[u] = {"u": u, "wa": w, "p": hp(pw), "t": int(time.time())}; return True
                if not upd(uf, f, {}): return 409, {"error": "Username atau nomor sudah terdaftar"}
                return 200, {"token": mk(u, c), "user": u}
            if a == "login":
                i = str(b.get("id", "")).strip().lower(); pw = str(b.get("password", ""))
                if throttle(i): return 429, {"error": "Terlalu banyak percobaan. Coba lagi 10 menit lagi."}
                if i == c["admin_user"].lower():
                    if not hmac.compare_digest(pw.encode(), c["admin_pass"].encode()): return 401, {"error": "Username/nomor atau kata sandi salah"}
                    FAIL.pop(i, None)
                    return 200, {"token": mk(i, c, 1), "user": i, "admin": True}
                k, v = find(us, i)
                if not v or not cp(pw, v["p"]): return 401, {"error": "Username/nomor atau kata sandi salah"}
                FAIL.pop(i, None)
                if v.get("s"):  # disuspend admin -> wajib verifikasi OTP WhatsApp
                    e = send_code("unsuspend:" + v["wa"], v["wa"], c)
                    return 403, {"suspended": True, "error": "Akun ditangguhkan admin. " + (e or f"Kode verifikasi dikirim ke WhatsApp {v['wa'][:4]}****{v['wa'][-3:]}.")}
                return 200, {"token": mk(k, c), "user": v["u"]}
            if a == "verify":
                k, v = find(us, b.get("id", ""))
                if not v or not v.get("s") or not chk("unsuspend:" + v["wa"], b.get("code", ""), c): return 400, {"error": "Kode salah atau kedaluwarsa"}
                upd(uf, lambda o: o[k].pop("s", None), {})
                return 200, {"token": mk(k, c), "user": v["u"]}
            if a == "reset":
                k, v = find(us, b.get("id", "")); pw = str(b.get("password", ""))
                if len(pw) < 6: return 400, {"error": "Kata sandi minimal 6 karakter"}
                if not v or not chk("reset:" + v["wa"], b.get("code", ""), c): return 400, {"error": "Kode salah atau kedaluwarsa"}
                upd(uf, lambda o: o[k].update(p=hp(pw)), {})
                return 200, {"ok": True}
            if a == "me":
                d = self.tok(c)
                if d and d.get("a") and d["u"] == c["admin_user"].lower(): return 200, {"user": d["u"], "admin": True, "token": mk(d["u"], c, 1)}
                v = us.get(d["u"] if d else "")
                if not v: return 401, {"error": "Sesi berakhir"}
                if v.get("s"): return 403, {"suspended": True, "error": "Akun ditangguhkan"}
                return 200, {"user": v["u"], "wa": v["wa"], "token": mk(d["u"], c)}

        if p[:2] == ["api", "db"] and len(p) in (3, 4):  # database JSON per user: data_dir/db/<user>/<collection>.json
            u = self.user(c, us)
            if not u: return 401, {"error": "Perlu login"}
            col = p[2]; i = p[3] if len(p) == 4 else None
            if not re.fullmatch(r"[\w.-]{1,64}", col) or (i and not re.fullmatch(r"[\w.-]{1,64}", i)): return 400, {"error": "Nama collection/id tidak valid"}
            f = os.path.join(c["data_dir"], "db", u, col + ".json")
            if m == "GET":
                d = rj(f, {})
                if not i: return 200, d
                return (200, d[i]) if i in d else (404, {"error": "Tidak ditemukan"})
            if m == "DELETE" and i: upd(f, lambda o: o.pop(i, None), {}); return 200, {"ok": True}
            if m in ("POST", "PUT") and (i or m == "POST"):
                i = i or secrets.token_hex(6)
                upd(f, lambda o: o.__setitem__(i, b), {}); return 200, {"id": i}
            return 405, {"error": "Metode tidak didukung"}
        return 404, {"error": "Endpoint tidak ada"}

    def tok(self, c): return ck(self.headers.get("Authorization", "")[7:], c)
    def is_admin(self, c):
        d = self.tok(c)
        return bool(d and d.get("a")) or hmac.compare_digest(self.headers.get("X-Admin-Key", ""), c["admin_key"])
    def user(self, c, us):
        d = self.tok(c); u = d and d["u"]
        return u if u in us and not us[u].get("s") else None

def main():
    a = sys.argv[1:] or ["run"]; c = conf()
    if a[0] == "run":
        os.makedirs(c["data_dir"], exist_ok=True)
        print(f"xapi di {c['host']}:{c['port']} | panel={c['panel']} | wa={c['wa_provider']}", flush=True)
        ThreadingHTTPServer((c["host"], int(c["port"])), H).serve_forever()
    elif a[0] == "config" and a[1:2] == ["set"] and len(a) >= 4:
        k, v = a[2], " ".join(a[3:])
        if k not in DEF: sys.exit("Kunci tidak dikenal. Pilihan: " + ", ".join(DEF))
        c[k] = v.lower() in ("1", "true", "on", "ya") if isinstance(DEF[k], bool) else int(v) if isinstance(DEF[k], int) else v
        wj(CONF, c); os.chmod(CONF, 0o600); print("OK:", k, "=", c[k])
    elif a[0] == "config":
        for k, v in c.items(): print(f"{k:12} {v if k not in ('secret', 'admin_pass') else '****'}")
    elif a[0] == "users":
        for v in rj(os.path.join(c["data_dir"], "users.json"), {}).values(): print(v["u"], v["wa"], "SUSPEND" if v.get("s") else "")
    else: print("Pakai: xapi.py [run | config [set KUNCI NILAI] | users]")

if __name__ == "__main__": main()
