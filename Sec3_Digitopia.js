const express = require("express");
const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");

const app = express();
app.use(express.json());


const penalties = {};
const reputation = {}; 

function getUserKey(req) {
  if (req.headers["x-user-id"]) return String(req.headers["x-user-id"]);
  return String(ipKeyGenerator(req));
}

function isArabic(req) {
  const lang = (req.headers["accept-language"] || "en").toLowerCase();
  return lang.startsWith("ar");
}

function nowMs() { return Date.now(); }
function humanMinutes(ms) { return Math.round(ms / 60000); }

function computeBlockMs(violations) {
  if (violations === 1) return 1 * 60 * 1000;      
  if (violations === 2) return 5 * 60 * 1000;      
  return 60 * 60 * 1000;                          
}

function detectTorVpn(req, res, next) {
  const forwarded = req.headers["x-forwarded-for"];
  const via = req.headers["via"];
  const torHeader = req.headers["x-tor-exit-node"];

  let suspicious = false;
  if (forwarded || via || torHeader) suspicious = true;


  if (forwarded && forwarded.split(",").length > 1) {
    suspicious = true;
  }

  req.isTorVpn = suspicious;
  next();
}
app.use(detectTorVpn);


function updateReputation(userKey, change) {
  if (!reputation[userKey]) {
    reputation[userKey] = { score: 100, lastUpdated: nowMs() }; 
  }
  reputation[userKey].score += change;
  reputation[userKey].lastUpdated = nowMs();

  reputation[userKey].score = Math.max(0, Math.min(200, reputation[userKey].score));
}

function getReputation(userKey) {
  return reputation[userKey] ? reputation[userKey].score : 100;
}


function checkBlocked(req, res, next) {
  const key = getUserKey(req);
  const entry = penalties[key];
  const now = nowMs();

  if (entry && entry.blockedUntil && entry.blockedUntil > now) {
    const remainingMs = entry.blockedUntil - now;
    const remainingMinutes = humanMinutes(remainingMs);

    const msgEn = `You are temporarily blocked. Please try again in ${remainingMinutes} minute${remainingMinutes === 1 ? '' : 's'}.`;
    const msgAr = remainingMinutes === 1 
      ? `أنت محظور مؤقتًا. حاول مرة أخرى بعد دقيقة واحدة.`
      : `أنت محظور مؤقتًا. حاول مرة أخرى بعد ${remainingMinutes} دقائق.`;

    return res.status(403).json({ 
      error: isArabic(req) ? msgAr : msgEn, 
      blockedForMinutes: remainingMinutes,
      remainingSeconds: Math.round(remainingMs / 1000)
    });
  }
  
  if (entry && entry.blockedUntil && entry.blockedUntil <= now) {
    entry.blockedUntil = 0;
  }
  
  return next();
}

function rateLimitHandlerFactory(max) {
  return function (req, res) {
    const key = getUserKey(req);
    const now = nowMs();
    if (!penalties[key]) penalties[key] = { violations: 0, blockedUntil: 0 };
    penalties[key].violations += 1;

    const blockMs = computeBlockMs(penalties[key].violations);
    penalties[key].blockedUntil = now + blockMs;
    const blockMinutes = humanMinutes(blockMs);

    updateReputation(key, -10);

    const msgEn = `Rate limit exceeded (${max} requests). You are temporarily blocked for ${blockMinutes} minute${blockMinutes === 1 ? '' : 's'}.`;
    const msgAr = blockMinutes === 1
      ? `تجاوزت الحد المسموح (${max} طلبات). تم حظرك مؤقتًا لمدة دقيقة واحدة.`
      : `تجاوزت الحد المسموح (${max} طلبات). تم حظرك مؤقتًا لمدة ${blockMinutes} دقائق.`;

    return res.status(429).json({
      error: isArabic(req) ? msgAr : msgEn,
      limit: max,
      blockedForMinutes: blockMinutes,
      violations: penalties[key].violations,
      unblockTime: new Date(penalties[key].blockedUntil).toISOString(),
      reputation: getReputation(key),
      torVpnSuspected: req.isTorVpn
    });
  };
}

function makeLimiter({ windowMs, max }) {
  return rateLimit({
    windowMs,
    max,
    keyGenerator: getUserKey,
    handler: rateLimitHandlerFactory(max),
    legacyHeaders: false
  });
}

const reportLimiter = makeLimiter({ windowMs: 24 * 60 * 60 * 1000, max: 5 });
const browseLimiter  = makeLimiter({ windowMs: 60 * 60 * 1000,  max: 100 });
const uploadLimiter  = makeLimiter({ windowMs: 24 * 60 * 60 * 1000, max: 10 });


app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/report", checkBlocked, reportLimiter, (req, res) => {
  updateReputation(getUserKey(req), +5);
  return res.json({ 
    ok: true, 
    message: isArabic(req) ? "تم استلام البلاغ." : "Report received.",
    reputation: getReputation(getUserKey(req)),
    torVpnSuspected: req.isTorVpn
  });
});

app.get("/browse", checkBlocked, browseLimiter, (req, res) => {
  return res.json({ 
    ok: true,
    torVpnSuspected: req.isTorVpn
  });
});

app.post("/upload", checkBlocked, uploadLimiter, (req, res) => {
  updateReputation(getUserKey(req), +2);
  return res.json({ 
    ok: true, 
    message: isArabic(req) ? "تم رفع الملف بنجاح." : "File uploaded successfully.",
    reputation: getReputation(getUserKey(req)),
    torVpnSuspected: req.isTorVpn
  });
});


app.get("/admin/penalties", (req, res) => res.json({ penalties, reputation }));

app.post("/admin/clear", express.json(), (req, res) => {
  const user = req.body.user;
  if (!user) return res.status(400).json({ error: "user required" });
  delete penalties[user];
  delete reputation[user];
  return res.json({ ok: true, cleared: user });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, "127.0.0.1", () => {
  console.log(`🚀 Demo running at http://127.0.0.1:${PORT}`);
});
