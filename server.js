// server.js — Node 18+
const express = require("express");
const path = require("path");
const dns = require("dns").promises;
const net = require("net");
const config = require("./config");

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ---------- rate limiter بسيط في الذاكرة ----------
const ipBuckets = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const win = 60_000;
  let bucket = ipBuckets.get(ip);
  if (!bucket || now - bucket.start > win) {
    bucket = { start: now, count: 0 };
    ipBuckets.set(ip, bucket);
  }
  bucket.count++;
  if (bucket.count > config.maxRequestsPerMinutePerIp) {
    return res.status(429).json({ error: "too many requests" });
  }
  next();
}
app.use("/api/", rateLimit);

// ---------- أدوات ----------
const EMAIL_RE = /^[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})$/i;

function rootDomainOf(host) {
  // simplified: last 2 labels or last 3 if 2nd-level suffix like co.uk / org.uk / ac.uk / gov.uk
  const parts = host.toLowerCase().split(".");
  const twoLevelSuffixes = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk",
    "plc.uk", "net.uk", "sch.uk", "nhs.uk",
  ]);
  const last2 = parts.slice(-2).join(".");
  if (twoLevelSuffixes.has(last2)) {
    return parts.slice(-3).join(".");
  }
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

// فحص MX للدومين الجذري
async function getMx(domain) {
  const mx = await safe(dns.resolveMx(domain));
  if (!mx.ok || !mx.value.length) return { ok: false, records: [] };
  const sorted = mx.value.sort((a, b) => a.priority - b.priority);
  return { ok: true, records: sorted.map(m => m.exchange) };
}

// فحص SPF/DMARC للدومين الجذري
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

// فحص SMTP — greeting + MAIL FROM + RCPT TO بدون DATA
// يرجع {ok: true|false|'unknown', code, message, mxHost}
function smtpVerify(mxHost, email, opts = {}) {
  return new Promise((resolve) => {
    const timeout = opts.timeout || config.smtpTimeoutMs;
    const sock = net.createConnection({ host: mxHost, port: config.smtpPort });
    let step = "greet";
    let buffer = "";
    let resolved = false;

    const finish = (result) => {
      if (resolved) return;
      resolved = true;
      try { sock.destroy(); } catch {}
      resolve(result);
    };

    sock.setTimeout(timeout);
    sock.on("timeout", () => finish({ ok: "unknown", reason: "timeout", mxHost }));
    sock.on("error", (e) => finish({ ok: "unknown", reason: e.code || e.message, mxHost }));

    sock.on("connect", () => sock.write(`EHLO ${config.heloHost}\r\n`));

    sock.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      // نفصل الردود على أساس \r\n
      let idx;
      while ((idx = buffer.indexOf("\r\n")) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        // سطر متعدد: نستمر لو الرابع '-'
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
          // 4xx = greylist / rate limit / try later → unknown
          return finish({ ok: "unknown", code, message: msg, mxHost });
        }
      }
    });
  });
}

// ---------- API ----------
app.get("/api/config", (req, res) => {
  res.json({
    allowedDomains: config.allowedDomains,
    bigProviderDomains: config.bigProviderDomains,
    maxEmailsPerRequest: config.maxEmailsPerRequest,
    smtpEnabled: config.smtpPort === 25,
  });
});

app.post("/api/check", async (req, res) => {
  const raw = Array.isArray(req.body?.emails) ? req.body.emails : [];
  const doSmtp = !!req.body?.smtp;
  if (!raw.length) return res.status(400).json({ error: "no emails provided" });
  if (raw.length > config.maxEmailsPerRequest)
    return res.status(400).json({ error: `max ${config.maxEmailsPerRequest} emails per request` });

  // تنظيف + فلترة
  const cleaned = [];
  const rejected = [];
  for (const e of raw) {
    const email = String(e || "").trim().toLowerCase();
    if (!email) continue;
    const m = EMAIL_RE.exec(email);
    if (!m) { rejected.push({ email, reason: "invalid format" }); continue; }
    const host = m[1];
    if (!isAllowed(host)) {
      rejected.push({ email, reason: "domain not allowed" });
      continue;
    }
    cleaned.push({ email, host, root: rootDomainOf(host) });
  }

  // استعلامات DNS لكل دومين جذري (مع cache داخلي للطلب)
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

  // شغل SMTP بالتزامن المحدود (4 في نفس الوقت) لتجنّب rate limits
  async function checkOne(item) {
    const policy = await getPolicy(item.root);
    const mx = await getMxSafe(item.root);
    const out = {
      email: item.email,
      host: item.host,
      root: item.root,
      formatOk: true,
      mxOk: mx.ok,
      mxHost: mx.records[0] || null,
      spf: policy.spf,
      dmarc: policy.dmarc,
      smtp: null,
    };

    if (doSmtp && mx.ok) {
      if (config.bigProviderDomains.includes(item.root)) {
        out.smtp = { ok: "unknown", reason: "big provider - smtp check skipped", mxHost: out.mxHost };
      } else {
        out.smtp = await smtpVerify(out.mxHost, item.email);
      }
    }
    return out;
  }

  const results = [];
  const queue = cleaned.slice();
  const workers = Array.from({ length: Math.min(4, queue.length) }, async () => {
    while (queue.length) {
      const item = queue.shift();
      try { results.push(await checkOne(item)); }
      catch (e) { results.push({ email: item.email, error: e.message }); }
    }
  });
  await Promise.all(workers);

  // ملخص
  const summary = {
    total: cleaned.length + rejected.length,
    accepted: cleaned.length,
    rejected: rejected.length,
    smtpChecked: results.filter(r => r.smtp && r.smtp.ok === true).length,
    smtpRejected: results.filter(r => r.smtp && r.smtp.ok === false).length,
    smtpUnknown: results.filter(r => r.smtp && r.smtp.ok === "unknown").length,
    byDomain: {},
  };
  for (const r of results) {
    if (!r.root) continue;
    summary.byDomain[r.root] = summary.byDomain[r.root] || { count: 0, mxOk: 0, spf: false, dmarc: false };
    summary.byDomain[r.root].count++;
    if (r.mxOk) summary.byDomain[r.root].mxOk++;
    if (r.spf) summary.byDomain[r.root].spf = true;
    if (r.dmarc) summary.byDomain[r.root].dmarc = true;
  }

  res.json({ summary, results, rejected });
});

app.listen(config.port, () => {
  console.log(`UK Email Checker → http://localhost:${config.port}`);
  console.log(`Allowed domains: ${config.allowedDomains.join(", ")}`);
});
