// Shield Web MVP - client-side only

const inputText = document.getElementById("inputText");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const demoBtn = document.getElementById("demoBtn");

const scoreEl = document.getElementById("score");
const scoreTagEl = document.getElementById("scoreTag");
const reasonsEl = document.getElementById("reasons");
const linksEl = document.getElementById("links");
const actionEl = document.getElementById("action");

// --- Simple heuristics (tune over time) ---
const urgencyWords = [
  "urgent","immediately","asap","now","today","within","final notice","last warning",
  "suspended","blocked","locked","verify","confirm","security alert","action required"
];

const paymentWords = [
  "pay","payment","invoice","refund","transfer","wire","card","otp","code",
  "vipps","bankid","konto","betal","faktura","refusjon","overfør","vipps meg"
];

const authorityTriggers = [
  "bank","police","skatteetaten","toll","customs","delivery","posten","dhl","ups",
  "account","konto","support","customer service"
];

// Common “link tricks”
const suspiciousLinkHints = [
  "login","verify","secure","support","account","update","confirm"
];

// URL extractor
function extractUrls(text) {
  const re = /((https?:\/\/|www\.)[^\s<>"']+)/gi;
  const matches = text.match(re);
  return matches ? matches.map(s => s.trim()) : [];
}

function normalizeUrl(url) {
  let u = url.trim();
  if (u.startsWith("www.")) u = "https://" + u;
  return u;
}

function getHostname(url) {
  try {
    const u = new URL(normalizeUrl(url));
    return u.hostname.toLowerCase();
  } catch {
    // fallback: crude parse
    return url.toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  }
}

function looksSuspiciousDomain(hostname) {
  // Heuristics: many hyphens, very long host, odd patterns
  const hyphens = (hostname.match(/-/g) || []).length;
  if (hyphens >= 3) return true;
  if (hostname.length > 40) return true;

  // lots of digits
  const digits = (hostname.match(/\d/g) || []).length;
  if (digits >= 6) return true;

  // known “cheap” patterns (not always scam)
  if (hostname.includes("secure-") || hostname.includes("-secure")) return true;
  if (hostname.includes("verify-") || hostname.includes("-verify")) return true;

  return false;
}

function containsManyHints(url) {
  const lower = url.toLowerCase();
  const hits = suspiciousLinkHints.filter(w => lower.includes(w)).length;
  return hits >= 2;
}

function countHits(lowerText, words) {
  let count = 0;
  for (const w of words) {
    if (lowerText.includes(w)) count++;
  }
  return count;
}

function riskLabel(score) {
  if (score >= 85) return { tag: "HIGH RISK", advice: "Do NOT click. Do NOT send money. Verify via official channel." };
  if (score >= 60) return { tag: "RISKY", advice: "Be careful. Verify the sender and link independently." };
  if (score >= 35) return { tag: "SUSPICIOUS", advice: "Proceed with caution. Look for red flags." };
  return { tag: "LOW RISK", advice: "No strong scam signals detected. Still verify if money/credentials are involved." };
}

function analyze(text) {
  const lower = text.toLowerCase();
  const urls = extractUrls(text).map(normalizeUrl);

  let score = 0;
  const reasons = [];

  // Links are a primary vector
  if (urls.length > 0) {
    score += 22;
    reasons.push("Contains link(s) — common phishing vector.");
  }

  // Urgency / pressure
  const uHits = countHits(lower, urgencyWords);
  if (uHits > 0) {
    score += Math.min(10 + uHits * 6, 26);
    reasons.push("Uses urgency/pressure language.");
  }

  // Payment / credential pressure
  const pHits = countHits(lower, paymentWords);
  if (pHits > 0) {
    score += Math.min(12 + pHits * 5, 28);
    reasons.push("Mentions payments/credentials (OTP, BankID, card) — common scam pattern.");
  }

  // Authority / fear triggers
  const aHits = countHits(lower, authorityTriggers);
  if (aHits > 0) {
    score += Math.min(aHits * 5, 15);
    reasons.push("References authority/service (bank, delivery, tax, police) — often impersonated.");
  }

  // Domain heuristics
  let domainFlagged = false;
  let hintFlagged = false;

  for (const url of urls) {
    const host = getHostname(url);

    if (looksSuspiciousDomain(host)) {
      domainFlagged = true;
    }
    if (containsManyHints(url)) {
      hintFlagged = true;
    }
  }

  if (domainFlagged) {
    score += 20;
    reasons.push("Link hostname looks suspicious (long, many hyphens/digits, ‘secure/verify’ pattern).");
  }
  if (hintFlagged) {
    score += 10;
    reasons.push("Link contains multiple high-risk keywords (login/verify/secure/support).");
  }

  // If message asks to act + has link, bump
  if (urls.length > 0 && (uHits > 0 || pHits > 0)) {
    score += 8;
    reasons.push("Link + pressure language combo is a classic phishing signature.");
  }

  score = Math.max(0, Math.min(100, score));

  const { tag, advice } = riskLabel(score);

  return { score, tag, advice, urls, reasons: [...new Set(reasons)] };
}

function render(result) {
  scoreEl.textContent = String(result.score);
  scoreTagEl.textContent = result.tag;

  reasonsEl.innerHTML = "";
  if (result.reasons.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No strong scam indicators detected (based on this MVP’s heuristics).";
    reasonsEl.appendChild(li);
  } else {
    for (const r of result.reasons) {
      const li = document.createElement("li");
      li.textContent = r;
      reasonsEl.appendChild(li);
    }
  }

  linksEl.textContent = result.urls.length ? result.urls.join("\n") : "–";
  actionEl.textContent = result.advice;
}

analyzeBtn.addEventListener("click", () => {
  const text = inputText.value.trim();
  if (!text) {
    alert("Paste some text first.");
    return;
  }
  const result = analyze(text);
  render(result);
});

clearBtn.addEventListener("click", () => {
  inputText.value = "";
  scoreEl.textContent = "–";
  scoreTagEl.textContent = "Paste text and press Analyze";
  reasonsEl.innerHTML = "";
  linksEl.textContent = "–";
  actionEl.textContent = "–";
});

demoBtn.addEventListener("click", () => {
  inputText.value =
`[Bank] Security alert: Your account is suspended.
Verify immediately to avoid closure: https://secure-login-verify-now-123.com
If you do not confirm within 2 hours, access will be blocked.`;
});
