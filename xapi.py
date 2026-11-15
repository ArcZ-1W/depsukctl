#!/usr/bin/env python3
# xapi: API auth (verifikasi WhatsApp) + database JSON lokal. Hanya stdlib, tanpa pip.
# Jalankan: python3 xapi.py run | python3 xapi.py config [set KUNCI NILAI] | python3 xapi.py users
import json, os, sys, re, time, hmac, hashlib, base64, secrets, threading, subprocess, urllib.request, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

CONF = os.environ.get("XAPI_CONF", "/etc/xapi/config.json")
DEF = {"host": "127.0.0.1", "port": 8787, "data_dir": "/var/lib/xapi", "cors": "*", "panel": True,
       "wa_provider": "console", "wa_token": "", "otp_ttl": 300, "token_days": 30, "secret": "", "admin_key": ""}
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

def mk(u, c):
    b = base64.urlsafe_b64encode(json.dumps({"u": u, "e": int(time.time()) + c["token_days"] * 86400}).encode()).decode()
    return b + "." + sign(b, c)

def ck(t, c):
    try:
        b, s = t.split(".")
        d = json.loads(base64.urlsafe_b64decode(b))
        return d["u"] if hmac.compare_digest(s, sign(b, c)) and d["e"] > time.time() else None
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

def sh(cmd):
    try:
        r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
        return (r.stdout or r.stderr).strip() or "ok"
    except Exception as e: return "gagal: " + str(e)

PANEL = r'''<!DOCTYPE html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark">
<title>Panel Xozen</title>
<style>
:root{--bg:#fff;--in:#f4f6fb;--line:#dfe4f0;--text:#1a1c24;--mute:#7d8397;--acc:#4d6bfe;--danger:#d93838}
@media(prefers-color-scheme:dark){:root{--bg:#16171b;--in:#1d1e23;--line:#33353e;--text:#eceef5;--mute:#8d93a6;--danger:#ff7b7b}}
*{box-sizing:border-box;margin:0}[hidden]{display:none!important}
body{padding:20px 16px 40px;background:var(--bg);color:var(--text);font:15px/1.5 Inter,"Segoe UI",system-ui,sans-serif}
main{max-width:520px;margin:0 auto}
.brand{font-size:26px;font-weight:800;letter-spacing:-.03em;color:var(--acc)}
section{border:1px solid var(--line);border-radius:20px;padding:16px;margin:14px 0}
h2{font-size:16px;font-weight:600;margin-bottom:10px}
label{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:8px 0;font-size:14px}
input,select{height:42px;padding:0 14px;border-radius:999px;border:1px solid var(--line);background:var(--in);color:var(--text);font:inherit;outline:0;min-width:0}
label input:not([type=checkbox]),label select{width:55%}
input[type=checkbox]{width:22px;height:22px;accent-color:var(--acc)}
input:focus,select:focus{border-color:var(--acc)}
button{font:inherit;cursor:pointer;height:42px;padding:0 18px;border-radius:999px;border:1px solid var(--line);background:none;color:var(--text)}
.p{background:var(--acc);border-color:var(--acc);color:#fff;width:100%;margin-top:10px}
.d{color:var(--danger);border-color:var(--danger)}.l{border:0;color:var(--acc)}
.row{display:flex;gap:8px;align-items:center;justify-content:space-between;margin:8px 0;flex-wrap:wrap}.row input{flex:1}
.kv{display:grid;grid-template-columns:1fr auto;gap:4px 12px}
.mute,.t{color:var(--mute)}.t{font-size:13px}
#msg{min-height:22px;margin-top:8px;color:var(--danger);font-size:14px}#msg.ok{color:var(--acc)}
code{background:var(--in);padding:1px 6px;border-radius:6px}
</style></head><body><main>
<div class="brand">Xozen <span class="mute" style="font-size:15px;font-weight:400">Panel</span></div>
<p id="msg" role="alert"></p>
<section id="lock"><h2>Masuk</h2><div class="row"><input id="key" type="password" placeholder="Admin key"><button id="go">Masuk</button></div>
<p class="t">Admin key ada di terminal: <code>xctl config</code></p></section>
<div id="app" hidden>
<section><h2>Status</h2><div class="kv" id="st"></div></section>
<section><h2>Pengaturan</h2><form id="cf"></form></section>
<section><h2>Tes WhatsApp</h2><div class="row"><input id="to" placeholder="08xx / 628xx"><button id="tw">Kirim tes</button></div></section>
<section><h2>Tunnel Cloudflare</h2>
<div class="row"><input id="tk" type="password" placeholder="Token baru"><button id="tks">Simpan</button></div>
<div class="row"><button data-t="on">Aktifkan</button><button data-t="off">Nonaktifkan</button><button data-t="restart">Restart</button></div></section>
<section><h2>Server</h2><div class="row"><button data-s="restart">Restart</button><button class="d" data-s="stop">Matikan</button></div>
<p class="t">Menyalakan lagi setelah dimatikan lewat terminal: <code>xctl start</code></p></section>
<section><h2>Pengguna</h2><div id="us"></div></section>
<button class="l" id="out">Keluar</button></div></main>
<script>
const $=s=>document.querySelector(s);let K=sessionStorage.getItem("xk")||"";
const esc=s=>String(s).replace(/[&<>"]/g,c=>"&#"+c.charCodeAt(0)+";");
const say=(t,ok)=>{const m=$("#msg");m.textContent=t||"";m.className=ok?"ok":""};
async function api(path,method,body){let r;
 try{r=await fetch("/admin/"+path,{method:method||"GET",headers:{"X-Admin-Key":K,"Content-Type":"application/json"},body:body?JSON.stringify(body):undefined})}catch(e){throw Error("Server tidak terjangkau")}
 const j=await r.json().catch(()=>({}));if(!r.ok)throw Error(j.error||"Gagal ("+r.status+")");return j}
const F=[["panel","Panel admin aktif","bool"],["host","Host","text"],["port","Port","number"],["cors","CORS origin","text"],["wa_provider","Pengirim WhatsApp","sel"],["wa_token","Token WhatsApp (Fonnte)","password"],["otp_ttl","Masa berlaku kode (detik)","number"],["token_days","Masa login (hari)","number"],["data_dir","Folder data","text"],["admin_key","Admin key","password"]];
function form(c){$("#cf").innerHTML=F.map(([k,l,t])=>"<label>"+l+(t==="sel"?`<select name="${k}">`+["console","fonnte"].map(o=>`<option${c[k]===o?" selected":""}>${o}</option>`).join("")+"</select>":t==="bool"?`<input name="${k}" type="checkbox"${c[k]?" checked":""}>`:`<input name="${k}" type="${t}" value="${esc(c[k])}" autocomplete="off">`)+"</label>").join("")+'<button class="p">Simpan pengaturan</button><p class="t">Perubahan host dan port butuh restart server.</p>'}
async function load(){
 try{const[s,c,u]=await Promise.all([api("status"),api("config"),api("users")]);
  $("#st").innerHTML=`<span>Server</span><b>${esc(s.server)}</b><span>Tunnel</span><b>${esc(s.tunnel)}</b><span>Pengguna</span><b>${s.users}</b>`;
  form(c);
  $("#us").innerHTML=u.length?u.map(x=>`<div class="row"><span>${esc(x.username)} <small class="mute">${esc(x.wa)}</small></span><button class="d" data-del="${esc(x.username)}">Hapus</button></div>`).join(""):"<p class=\"t\">Belum ada pengguna.</p>";
  $("#lock").hidden=true;$("#app").hidden=false;
 }catch(e){$("#lock").hidden=false;$("#app").hidden=true;say(e.message)}}
$("#go").onclick=()=>{K=$("#key").value.trim();sessionStorage.setItem("xk",K);say("");load()};
$("#cf").onsubmit=async e=>{e.preventDefault();const o={};
 F.forEach(([k,,t])=>{const el=e.target.elements[k];o[k]=t==="bool"?el.checked:t==="number"?Number(el.value):el.value});
 if(!o.panel&&!confirm("Panel akan nonaktif dan halaman ini tidak bisa dibuka lagi. Aktifkan kembali lewat terminal: xctl panel on. Lanjut?"))return;
 try{const j=await api("config","PUT",o);K=o.admin_key;sessionStorage.setItem("xk",K);say(j.restart?"Tersimpan. Restart server agar host/port berlaku.":"Tersimpan.",1)}catch(x){say(x.message)}};
$("#tw").onclick=async()=>{try{await api("testwa","POST",{to:$("#to").value});say("Pesan tes terkirim.",1)}catch(x){say(x.message)}};
$("#tks").onclick=async()=>{try{await api("tunnel","POST",{token:$("#tk").value});$("#tk").value="";say("Token disimpan, tunnel direstart.",1);load()}catch(x){say(x.message)}};
$("#out").onclick=()=>{sessionStorage.removeItem("xk");location.reload()};
document.addEventListener("click",async e=>{const b=e.target.closest("button"),d=b&&b.dataset;if(!d)return;
 try{
  if(d.t){await api("tunnel","POST",{action:d.t});say("Tunnel: "+d.t+" selesai.",1);load()}
  else if(d.s){if(!confirm(d.s==="stop"?"Matikan server? Panel ikut mati sampai kamu jalankan xctl start.":"Restart server?"))return;
   await api("server","POST",{action:d.s});say(d.s==="stop"?"Server dimatikan.":"Restart dikirim. Muat ulang halaman beberapa detik lagi.",1)}
  else if(d.del){if(!confirm("Hapus pengguna "+d.del+"?"))return;await api("users/"+d.del,"DELETE");load()}
 }catch(x){say(x.message)}});
if(K)load();
</script></body></html>'''

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
    def page(self, c):  # GET /panel: HTML tertanam di file ini, aktif selama panel=true
        if not c["panel"]: return self.out(403, {"error": "Panel dinonaktifkan. Aktifkan lewat terminal: xctl panel on"})
        b = PANEL.encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY"); self.end_headers(); self.wfile.write(b)
    def route(self):
        if self.command == "GET" and urllib.parse.urlparse(self.path).path.rstrip("/") == "/panel": return self.page(conf())
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000: return self.out(413, {"error": "Data terlalu besar"})
            b = json.loads(self.rfile.read(n)) if n else {}
            if not isinstance(b, dict): raise ValueError
        except Exception: return self.out(400, {"error": "Body harus JSON object"})
        try: self.out(*self.handle(conf(), self.command, urllib.parse.urlparse(self.path).path.strip("/").split("/"), b))
        except Exception as e:
            print("ERR", repr(e), flush=True); self.out(500, {"error": "Kesalahan server"})
    do_GET = do_POST = do_PUT = do_DELETE = route

    def handle(self, c, m, p, b):
        uf = os.path.join(c["data_dir"], "users.json"); us = rj(uf, {})
        if p in ([""], ["health"]): return 200, {"ok": True, "app": "xapi"}

        if p[0] == "admin":  # panel admin: header X-Admin-Key, bisa dimatikan (panel=false)
            if not c["panel"]: return 403, {"error": "Panel dinonaktifkan"}
            if not hmac.compare_digest(self.headers.get("X-Admin-Key", "").encode(), c["admin_key"].encode()):
                return (429, {"error": "Terlalu banyak percobaan"}) if throttle("admin") else (401, {"error": "Admin key salah"})
            s = p[1] if len(p) > 1 else ""
            if s == "status":
                tun = sh("systemctl is-active xtunnel") if os.path.exists("/etc/systemd/system/xtunnel.service") else "belum dipasang"
                return 200, {"server": "aktif", "tunnel": tun, "users": len(us)}
            if s == "config" and m == "GET": return 200, {k: v for k, v in c.items() if k != "secret"}
            if s == "config" and m == "PUT":
                n = {}
                for k, v in b.items():
                    if k not in DEF or k == "secret": return 400, {"error": "Kunci tidak dikenal: " + k}
                    n[k] = bool(v) if isinstance(DEF[k], bool) else int(v) if isinstance(DEF[k], int) else str(v)
                c.update(n); wj(CONF, c); os.chmod(CONF, 0o600)
                return 200, {"ok": True, "restart": "host" in n or "port" in n}
            if s == "tunnel" and m == "POST":
                if b.get("token"):
                    t = re.search(r"eyJ[A-Za-z0-9_=+/-]+", str(b["token"]))
                    if not t: return 400, {"error": "Token tidak valid"}
                    if not os.path.exists("/etc/systemd/system/xtunnel.service"): return 400, {"error": "Tunnel belum dipasang. Jalankan sekali: xctl tunnel token"}
                    env = os.path.join(os.path.dirname(CONF), "tunnel.env")
                    with open(env, "w") as f: f.write("TUNNEL_TOKEN=" + t.group() + "\n")
                    os.chmod(env, 0o600); sh("systemctl restart xtunnel"); return 200, {"ok": True}
                cmd = {"on": "enable --now", "off": "disable --now", "restart": "restart"}.get(b.get("action"))
                if not cmd: return 400, {"error": "action harus on, off, atau restart"}
                return 200, {"out": sh("systemctl " + cmd + " xtunnel")}
            if s == "server" and m == "POST" and b.get("action") in ("restart", "stop"):
                threading.Timer(1, sh, ["systemctl --no-block " + b["action"] + " xapi"]).start(); return 200, {"ok": True}
            if s == "testwa" and m == "POST":
                w = norm(b.get("to", ""))
                if not w: return 400, {"error": "Nomor tidak valid"}
                try: wa(w, "Tes WhatsApp dari panel Xozen berhasil.", c)
                except Exception as e: return 502, {"error": "Gagal kirim: " + str(e)}
                return 200, {"ok": True}
            if s == "users" and m == "GET": return 200, [{"username": v["u"], "wa": v["wa"]} for v in us.values()]
            if s == "users" and m == "DELETE" and len(p) == 3: upd(uf, lambda o: o.pop(p[2].lower(), None), {}); return 200, {"ok": True}
            return 404, {"error": "Tidak ada"}

        if p[:2] == ["api", "auth"] and len(p) == 3:
            a = p[2]
            if a == "code":
                pu = b.get("purpose"); w = norm(b.get("wa", ""))
                if pu == "reset":
                    _, v = find(us, b.get("id", ""))
                    if not v: return 200, {"ok": True}  # tidak membocorkan akun mana yang ada
                    w = v["wa"]
                elif pu == "register":
                    if not w: return 400, {"error": "Nomor WhatsApp tidak valid"}
                    if any(v["wa"] == w for v in us.values()): return 409, {"error": "Nomor sudah terdaftar"}
                else: return 400, {"error": "purpose harus register atau reset"}
                e = send_code(pu + ":" + w, w, c)
                return (429, {"error": e}) if e else (200, {"ok": True})
            if a == "register":
                u = str(b.get("username", "")).strip().lower(); w = norm(b.get("wa", "")); pw = str(b.get("password", ""))
                if not re.fullmatch(r"[a-z][a-z0-9_.]{2,19}", u): return 400, {"error": "Username 3-20 karakter, diawali huruf (a-z, 0-9, _ .)"}
                if not w or len(pw) < 6: return 400, {"error": "Nomor WhatsApp tidak valid atau kata sandi kurang dari 6 karakter"}
                if u in us: return 409, {"error": "Username sudah dipakai"}
                if not chk("register:" + w, b.get("code", ""), c): return 400, {"error": "Kode salah atau kedaluwarsa"}
                def f(o):
                    if u in o or any(v["wa"] == w for v in o.values()): return False
                    o[u] = {"u": u, "wa": w, "p": hp(pw), "t": int(time.time())}; return True
                if not upd(uf, f, {}): return 409, {"error": "Username atau nomor sudah terdaftar"}
                return 200, {"token": mk(u, c), "user": u}
            if a == "login":
                i = str(b.get("id", "")).strip().lower()
                if throttle(i): return 429, {"error": "Terlalu banyak percobaan. Coba lagi 10 menit lagi."}
                k, v = find(us, i)
                if not v or not cp(str(b.get("password", "")), v["p"]): return 401, {"error": "Username/nomor atau kata sandi salah"}
                FAIL.pop(i, None)
                return 200, {"token": mk(k, c), "user": v["u"]}
            if a == "reset":
                k, v = find(us, b.get("id", "")); pw = str(b.get("password", ""))
                if len(pw) < 6: return 400, {"error": "Kata sandi minimal 6 karakter"}
                if not v or not chk("reset:" + v["wa"], b.get("code", ""), c): return 400, {"error": "Kode salah atau kedaluwarsa"}
                upd(uf, lambda o: o[k].update(p=hp(pw)), {})
                return 200, {"ok": True}
            if a == "me":
                v = us.get(self.user(c, us) or "")
                return (200, {"user": v["u"], "wa": v["wa"]}) if v else (401, {"error": "Token tidak valid"})

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

    def user(self, c, us):
        u = ck(self.headers.get("Authorization", "")[7:], c)
        return u if u in us else None

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
        for k, v in c.items(): print(f"{k:12} {v if k != 'secret' else '****'}")
    elif a[0] == "users":
        for v in rj(os.path.join(c["data_dir"], "users.json"), {}).values(): print(v["u"], v["wa"])
    else: print("Pakai: xapi.py [run | config [set KUNCI NILAI] | users]")

if __name__ == "__main__": main()
