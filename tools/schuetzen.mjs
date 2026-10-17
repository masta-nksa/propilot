// Verschlüsselt eine HTML-Seite mit einem Zugangscode (AES-GCM, Schlüssel per PBKDF2)
// und schreibt eine Zugangsseite, die den Inhalt erst nach Eingabe des Codes im Browser entschlüsselt.
// Aufruf: node tools/schuetzen.mjs <quelle.html> <ausgabe.html>   (Code über die Umgebungsvariable ZUGANGSCODE)
import { readFileSync, writeFileSync } from "node:fs";
import { randomBytes, pbkdf2Sync, createCipheriv } from "node:crypto";

const [quelle, ausgabe] = process.argv.slice(2);
const code = (process.env.ZUGANGSCODE || "").trim().toUpperCase();
if (!quelle || !ausgabe || !code) {
  console.error("Aufruf: ZUGANGSCODE=... node tools/schuetzen.mjs <quelle.html> <ausgabe.html>");
  process.exit(1);
}

const ITER = 250000;
const salt = randomBytes(16), iv = randomBytes(12);
const key = pbkdf2Sync(code, salt, ITER, 32, "sha256");
const c = createCipheriv("aes-256-gcm", key, iv);
const ct = Buffer.concat([c.update(readFileSync(quelle)), c.final(), c.getAuthTag()]);
const payload = JSON.stringify({ i: ITER, s: salt.toString("base64"), v: iv.toString("base64"), c: ct.toString("base64") });

const seite = `<!doctype html>
<html lang="de-CH">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Projektwege NKSA</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,800&family=IBM+Plex+Sans:wght@400;600&display=swap">
<style>
:root{--bg:#f6f7f5;--surface:#fff;--ink:#1d2421;--muted:#5b655f;--line:#d6dad4;--sign:#f2c200;--sign-ink:#1d1a10;--accent:#1f6b52;--warn:#b4581c}
@media (prefers-color-scheme: dark){:root{--bg:#141917;--surface:#1c2320;--ink:#e6ebe7;--muted:#9aa59f;--line:#2f3934;--sign:#e8b900;--sign-ink:#17140a;--accent:#6cc4a1;--warn:#e59a5f;color-scheme:dark}}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--ink);font-family:"IBM Plex Sans","Segoe UI",system-ui,sans-serif;display:grid;place-items:center;padding:16px}
form{width:100%;max-width:380px;background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:28px;display:grid;gap:16px}
.sign{justify-self:start;background:var(--sign);color:var(--sign-ink);font-weight:700;font-size:.85rem;padding:.3em 1.2em .3em .7em;clip-path:polygon(0 0,calc(100% - .8em) 0,100% 50%,calc(100% - .8em) 100%,0 100%)}
h1{font-family:"Bricolage Grotesque","Segoe UI",system-ui,sans-serif;font-weight:800;font-size:1.7rem;margin:0;line-height:1.15}
p{margin:0;color:var(--muted);font-size:.95rem}
label{font-weight:600;font-size:.9rem}
input{font:inherit;font-size:1rem;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);letter-spacing:.08em;text-transform:uppercase;width:100%}
button{font:inherit;font-weight:600;padding:10px 14px;border-radius:8px;border:0;background:var(--accent);color:var(--bg);cursor:pointer}
input:focus-visible,button:focus-visible{outline:3px solid var(--sign);outline-offset:2px}
#err{color:var(--warn);font-size:.9rem;min-height:1.3em}
</style>
</head>
<body>
<form id="f" autocomplete="off">
  <span class="sign">Entwurf</span>
  <h1>Projektwege NKSA</h1>
  <p>Konzeptvorschlag zum Lehrmittel Projektunterricht. Bitte geben Sie den Zugangscode ein.</p>
  <div style="display:grid;gap:6px"><label for="code">Zugangscode</label><input id="code" name="code" autofocus required></div>
  <button type="submit">Öffnen</button>
  <div id="err" role="alert"></div>
</form>
<script>
const P=${payload};
const b64=s=>Uint8Array.from(atob(s),ch=>ch.charCodeAt(0));
async function oeffnen(code){
  const km=await crypto.subtle.importKey("raw",new TextEncoder().encode(code),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt:b64(P.s),iterations:P.i,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["decrypt"]);
  const html=new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:b64(P.v)},key,b64(P.c)));
  try{sessionStorage.setItem("pw-code",code)}catch(e){}
  document.open();document.write(html);document.close();
}
document.getElementById("f").addEventListener("submit",async e=>{
  e.preventDefault();
  const err=document.getElementById("err");err.textContent="";
  try{await oeffnen(document.getElementById("code").value.trim().toUpperCase())}
  catch(x){err.textContent="Der Code stimmt nicht. Bitte nochmals versuchen."}
});
try{const c=sessionStorage.getItem("pw-code");if(c)oeffnen(c).catch(()=>{})}catch(e){}
</script>
</body>
</html>
`;
writeFileSync(ausgabe, seite);
console.log("geschrieben:", ausgabe, Math.round(seite.length / 1024) + " KB");
