// index.js — Vercel entrypoint
const express = require("express");
const path = require("path");
const dns = require("dns").promises;
const net = require("net");
const config = require("./config");

const app = express();
app.use(express.json({ limit: "5mb" }));
app.use(express.static(path.join(__dirname, "public")));

const EMAIL_RE = /^[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})$/i;

function rootDomainOf(host) {
  const parts = host.toLowerCase().split(".");
  const twoLevelSuffixes = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk",
    "plc.uk", "net.uk", "sch.uk", "nhs.uk",
  ]);
  const last2 = parts.slice(-2).join(".");
  if (twoLevelSuffixes.has(last2)) return parts.slice(-3).join(".");
  return last2;
}

function isAllowed(host) {
  const root = rootDomainOf(host);
  return config.allowedDomains.some(d =>
    root === d || root.endsWith("." + d) || host === d || host.endsWith("." + d)
  );
}

async function safe(p) {
  try { return { ok: true, value: await p }; }
  catch (e) { return { ok: false, error: e.code || e.message }; }
}

async function getMx(domain) {
  const mx = await safe(dns.resolveMx(domain));
  if (!mx.ok || !mx.value.length) return { ok: false, records: [] };
  const sorted = mx.value.sort((a, b) => a.priority - b.priority);
  return { ok: true, records: sorted.map(m => m.exchange) };
}

async function getTxtPolicy(domain) {
  const root = rootDomainOf(domain);
  const out = { spf: null, dmarc: null };
  const txt = await safe(dns.resolveTxt(root));
  if (txt.ok) {
    for (const arr of txt.value) {
      const s = arr.join("");
      if (s.toLowerCase().startsWith("v=spf1")) { out.spf = s; break; }
    }
  }
  const dmarcTxt = await safe(dns.resolveTxt(`_dmarc.${root}`));
  if (dmarcTxt.ok) {
    for (const arr of dmarcTxt.value) {
      const s = arr.join("");
      if (s.toLowerCase().startsWith("v=dmarc1")) { out.dmarc = s; break; }
    }
  }
  return out;
}

function smtpVerify(mxHost, email, opts = {}) {
  return new Promise((resolve) => {
    const timeout = opts.timeout || config.smtpTimeoutMs;
    let sock;
    let resolved = false;
    const finish = (r) => {
      if (resolved) return;
      resolved = true;
      try { sock && sock.destroy(); } catch {}
      resolve(r);
    };
    try {
      sock = net.createConnection({ host: mxHost, port: config.smtpPort });
    } catch (e) {
      return finish({ ok: "unknown", reason: "connect: " + e.message, mxHost });
    }
    let step = "greet";
    let buffer = "";
    sock.setTimeout(timeout);
    sock.on("timeout", () => finish({ ok: "unknown", reason: "timeout", mxHost }));
    sock.on("error", (e) => finish({ ok: "unknown", reason: e.code || e.message, mxHost }));
    sock.on("connect", () => sock.write(`EHLO ${config.heloHost}\r\n`));
    sock.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let idx;
      while ((idx = buffer.indexOf("\r\n")) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        if (line.length >= 4 && line[3] === "-") continue;
        const code = parseInt(line.slice(0, 3), 10);
        const msg = line.slice(4);
        if (step === "greet") {
          if (code !== 220) return finish({ ok: "unknown", reason: `greet ${code}`, mxHost });
          step = "mailfrom";
          sock.write(`MAIL FROM:<${config.mailFrom}>\r\n`);
          return;
        }
        if (step === "mailfrom") {
          if (code !== 250) return finish({ ok: "unknown", reason: `mailfrom ${code}`, mxHost });
          step = "rcptto";
          sock.write(`RCPT TO:<${email}>\r\n`);
          return;
        }
        if (step === "rcptto") {
          if (code === 250 || code === 251) return finish({ ok: true, code, message: msg, mxHost });
          if (code === 550 || code === 551 || code === 553) return finish({ ok: false, code, message: msg, mxHost });
          return finish({ ok: "unknown", code, message: msg, mxHost });
        }
      }
    });
  });
}

// endpoint: معالجة دفعة واحدة، كل إيميل مستقل بـ try/catch
app.post("/api/check-batch", async (req, res) => {
  const raw = Array.isArray(req.body?.emails) ? req.body.emails : [];
  const doSmtp = !!req.body?.smtp;
  if (!raw.length) return res.status(400).json({ error: "no emails" });

  const policyCache = new Map();
  const mxCache = new Map();

  async function getPolicy(root) {
    if (!policyCache.has(root)) policyCache.set(root, await getTxtPolicy(root));
    return policyCache.get(root);
  }
  async function getMxSafe(root) {
    if (!mxCache.has(root)) mxCache.set(root, await getMx(root));
    return mxCache.get(root);
  }

  const results = [];
  // معالجة متوازية محدودة — 4 في نفس الوقت
  const queue = raw.map((e, i) => ({ idx: i, email: String(e || "").trim().toLowerCase() }));
  async function worker() {
    while (queue.length) {
      const item = queue.shift();
      if (!item || !item.email) continue;
      try {
        const m = EMAIL_RE.exec(item.email);
        if (!m) {
          results.push({
            idx: item.idx, email: item.email, status: "rejected",
            reason: "invalid format",
          });
          continue;
        }
        const host = m[1];
        if (!isAllowed(host)) {
          results.push({
            idx: item.idx, email: item.email, host,
            status: "rejected", reason: "domain not allowed",
          });
          continue;
        }
        const root = rootDomainOf(host);
        const [policy, mx] = await Promise.all([getPolicy(root), getMxSafe(root)]);

        const out = {
          idx: item.idx, email: item.email, host, root,
          status: "ok",
          mxOk: mx.ok, mxHost: mx.records[0] || null,
          spf: policy.spf, dmarc: policy.dmarc,
          smtp: null,
        };

        if (doSmtp && mx.ok) {
          try {
            if (config.bigProviderDomains.includes(root)) {
              out.smtp = { ok: "unknown", reason: "big provider - skipped" };
            } else {
              out.smtp = await smtpVerify(out.mxHost, item.email);
            }
          } catch (e) {
            out.smtp = { ok: "unknown", reason: "smtp exception: " + e.message };
          }
        }
        results.push(out);
      } catch (e) {
        results.push({
          idx: item.idx, email: item.email, status: "error",
          reason: e.message,
        });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(4, queue.length) }, worker));

  // ترتيب حسب idx الأصلي
  results.sort((a, b) => a.idx - b.idx);
  res.json({ results });
});

app.get("/api/config", (req, res) => {
  res.json({
    allowedDomains: config.allowedDomains,
    bigProviderDomains: config.bigProviderDomains,
  });
});

module.exports = app;

if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`UK Email Checker → http://localhost:${config.port}`);
  });
}
