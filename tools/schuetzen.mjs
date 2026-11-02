// Verschlüsselt eine HTML-Seite mit einem Zugangscode (AES-GCM, Schlüssel per PBKDF2)
// und schreibt eine Zugangsseite, die den Inhalt erst nach Eingabe des Codes im Browser entschlüsselt.
// Aufruf: node tools/schuetzen.mjs <quelle.html> <ausgabe.html>   (Code über die Umgebungsvariable ZUGANGSCODE)
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
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
const logo = readFileSync(fileURLToPath(new URL("../assets/logos/Web/Querformat/Orange/nksa_logo_web_quer_positiv_rgb_orange.png", import.meta.url))).toString("base64");
const payload = JSON.stringify({ i: ITER, s: salt.toString("base64"), v: iv.toString("base64"), c: ct.toString("base64") });

const seite = `<!doctype html>
<html lang="de-CH">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Projektwege NKSA</title>
<style>
:root{--bg:#f4f4f2;--surface:#fff;--ink:#111;--muted:#595959;--line:#d9d9d5;--sign:#ff890a;--sign-ink:#111;--btn:#ff890a;--btn-ink:#111;--warn:#b3261e;--f:"Helvetica Neue",Helvetica,Arial,"Segoe UI",sans-serif}
@media (prefers-color-scheme: dark){:root{--bg:#141414;--surface:#1e1e1e;--ink:#f2f2f2;--muted:#a6a6a6;--line:#363636;--warn:#ff8a80;color-scheme:dark}}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--f);display:grid;place-items:center;padding:16px}
form{width:100%;max-width:380px;background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:28px;display:grid;gap:16px}
.sign{justify-self:start;background:var(--sign);color:var(--sign-ink);font-weight:700;font-size:.85rem;padding:.3em 1.2em .3em .7em;clip-path:polygon(0 0,calc(100% - .8em) 0,100% 50%,calc(100% - .8em) 100%,0 100%)}
h1{font-family:var(--f);font-weight:800;font-size:1.7rem;margin:0;line-height:1.15}
p{margin:0;color:var(--muted);font-size:.95rem}
label{font-weight:600;font-size:.9rem}
input{font:inherit;font-size:1rem;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);letter-spacing:.08em;text-transform:uppercase;width:100%}
button{font:inherit;font-weight:700;padding:10px 14px;border-radius:8px;border:0;background:var(--btn);color:var(--btn-ink);cursor:pointer}
.logo{width:140px;aspect-ratio:1000/509;background:url("data:image/png;base64,${logo}") no-repeat left center/contain}
input:focus-visible,button:focus-visible{outline:3px solid var(--sign);outline-offset:2px}
#err{color:var(--warn);font-size:.9rem;min-height:1.3em}
</style>
</head>
<body>
<form id="f" autocomplete="off">
  <span class="logo" role="img" aria-label="NKSA, Neue Kantonsschule Aarau"></span>
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
