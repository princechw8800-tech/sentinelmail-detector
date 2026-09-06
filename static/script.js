const form = document.getElementById("emailForm");
const loading = document.getElementById("loading");
const errorBox = document.getElementById("error");
const result = document.getElementById("result");
const fileInput = document.getElementById("email_file");
const uploadZone = document.querySelector(".upload-zone");
const reportButton = document.getElementById("downloadReport");
let latestResult = null;
const historyKey = "sentinelmail-scan-history";
const samples = {
  safe: "From: Updates <news@company.example>\nTo: Demo <demo@example.test>\nSubject: Your monthly account update\nReceived: from mail.company.example\nAuthentication-Results: demo; spf=pass dkim=pass dmarc=pass\nContent-Type: text/plain\n\nHello, your monthly summary is now available in your account dashboard.",
  phishing: "From: Bank Security <security@trusted-bank.example>\nReply-To: recovery@account-alerts.example\nReturn-Path: <bounce@mailer-update.example>\nSubject: URGENT: Verify your password now\nReceived: from mailer-update.example\nAuthentication-Results: demo; spf=fail dkim=fail dmarc=fail\nContent-Type: text/plain\n\nURGENT: Your account is suspended. Click here to login: https://secure-account-check.example/login\nVerify your password immediately at https://billing-review.example/verify",
  invoice: "From: Vendor Billing <billing@vendor.example>\nReply-To: accounts@vendor-payments.example\nSubject: URGENT invoice payment required\nReceived: from unknown.example\nAuthentication-Results: demo; spf=softfail dkim=fail dmarc=fail\nContent-Type: text/plain\n\nYour invoice is overdue. Click here to login and verify payment: https://invoice-payment.example/login"
};

const bootScreen = document.getElementById("bootScreen");
const bootMessage = document.getElementById("bootMessage");
const bootSteps = ["INITIALIZING THREAT ENGINE", "LOADING FORENSIC MODULES", "SECURING ANALYSIS CHANNEL", "SYSTEM READY"];

bootSteps.forEach((message, index) => {
  setTimeout(() => { bootMessage.textContent = message; }, index * 530);
});
setTimeout(() => {
  bootScreen.classList.add("boot-complete");
  document.body.classList.add("dashboard-ready");
  setTimeout(() => bootScreen.remove(), 700);
}, 2200);

fileInput.addEventListener("change", () => {
  const selected = fileInput.files[0];
  uploadZone.classList.toggle("has-file", Boolean(selected));
  uploadZone.querySelector(".upload-title").textContent = selected ? selected.name : "DROP EMAIL EVIDENCE HERE";
});

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function highlightPreview(text) {
  const safe = text.replace(/[&<>]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[character]));
  return safe.replace(/\b(urgent|verify|password|login|account suspended|wire transfer|gift card|click here|limited time)\b/gi, '<mark>$1</mark>');
}

function renderAuthentication(status) {
  [["spfStatus", status.SPF], ["dkimStatus", status.DKIM], ["dmarcStatus", status.DMARC]].forEach(([id, value]) => {
    const element = document.getElementById(id);
    element.textContent = value;
    element.className = value === "PASS" ? "pass" : value.includes("FAIL") ? "fail" : "unknown";
  });
}

function renderUrls(urls) {
  const area = document.getElementById("urlDetails");
  if (!urls.length) { area.textContent = "No URLs were found in this email."; return; }
  area.replaceChildren(...urls.map((item) => {
    const row = document.createElement("div");
    row.className = `url-row ${item.risk === "Review" ? "url-review" : ""}`;
    row.innerHTML = `<strong>${item.domain}</strong><span>${item.risk}</span><small>${item.signals.join(" · ")}</small>`;
    return row;
  }));
}

function getHistory() {
  try { return JSON.parse(localStorage.getItem(historyKey) || "[]"); } catch { return []; }
}

function renderHistory() {
  const history = getHistory();
  const highRisk = history.filter((item) => item.score >= 55).length;
  const average = history.length ? Math.round(history.reduce((sum, item) => sum + item.score, 0) / history.length) : 0;
  document.getElementById("historyCount").textContent = `${history.length} SCAN${history.length === 1 ? "" : "S"}`;
  document.getElementById("highRiskCount").textContent = highRisk;
  document.getElementById("averageScore").textContent = `${average}%`;
  document.getElementById("lastVerdict").textContent = history[0]?.verdict || "—";
  const chart = document.getElementById("historyChart");
  chart.replaceChildren(...history.slice(0, 8).reverse().map((item) => {
    const bar = document.createElement("i");
    bar.style.height = `${Math.max(item.score, 7)}%`;
    bar.title = `${item.name}: ${item.score}%`;
    bar.className = item.score >= 55 ? "critical" : item.score >= 25 ? "warning" : "safe";
    return bar;
  }));
  const list = document.getElementById("historyList");
  list.replaceChildren(...(history.slice(0, 4).map((item) => {
    const row = document.createElement("div");
    row.innerHTML = `<span>${item.name}</span><small>${item.verdict}</small><b>${item.score}%</b>`;
    return row;
  })) || [Object.assign(document.createElement("span"), { textContent: "No scans in this browser yet." })]);
}

function saveHistory(data) {
  const name = fileInput.files[0]?.name || "Demo scan";
  const history = getHistory();
  history.unshift({ name, score: data.risk_score, verdict: data.classification });
  localStorage.setItem(historyKey, JSON.stringify(history.slice(0, 12)));
  renderHistory();
}

function animateGauge(score) {
  const gauge = document.getElementById("riskGauge");
  const label = document.getElementById("gaugeScore");
  gauge.style.setProperty("--score", score);
  const start = performance.now();
  const frame = (time) => {
    const value = Math.min(score, Math.round(score * Math.min((time - start) / 700, 1)));
    label.textContent = value;
    if (value < score) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

document.querySelectorAll(".demo-button").forEach((button) => button.addEventListener("click", () => {
  const type = button.dataset.demo;
  const transfer = new DataTransfer();
  transfer.items.add(new File([samples[type]], `${type}-demo.eml`, { type: "message/rfc822" }));
  fileInput.files = transfer.files;
  fileInput.dispatchEvent(new Event("change"));
  form.requestSubmit();
}));

renderHistory();

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  document.body.classList.add("is-scanning");
  errorBox.classList.add("hidden");
  result.classList.add("hidden");
  loading.classList.remove("hidden");

  try {
    const response = await fetch("/analyze", { method: "POST", body: new FormData(form) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Analysis failed.");
    latestResult = data;
    saveHistory(data);
    animateGauge(data.risk_score);

    document.getElementById("classification").textContent = data.classification;
    document.getElementById("riskScore").textContent = `${data.risk_score}%`;
    document.getElementById("sender").textContent = data.sender;
    document.getElementById("domain").textContent = data.domain;
    document.getElementById("replyTo").textContent = data.reply_to;
    document.getElementById("returnPath").textContent = data.return_path;
    document.getElementById("subject").textContent = data.subject;
    document.getElementById("received").textContent = data.received;
    document.getElementById("urls").textContent = data.urls;
    document.getElementById("authentication").textContent = data.authentication;
    renderAuthentication(data.auth_status);
    renderUrls(data.url_details);
    document.getElementById("emailPreview").innerHTML = highlightPreview(data.body_preview || "No readable message body was found.");
    document.getElementById("reasons").replaceChildren(...data.reasons.map((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      return item;
    }));
    result.classList.remove("hidden");
  } catch (error) {
    showError(error.message);
  } finally {
    loading.classList.add("hidden");
    document.body.classList.remove("is-scanning");
  }
});

reportButton.addEventListener("click", async () => {
  if (!latestResult) return showError("Analyze an email before downloading a report.");
  try {
    const response = await fetch("/report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(latestResult) });
    if (!response.ok) throw new Error("Could not generate the report.");
    const link = document.createElement("a");
    link.href = URL.createObjectURL(await response.blob());
    link.download = "sentinelmail-threat-report.pdf";
    link.click();
    URL.revokeObjectURL(link.href);
  } catch (error) { showError(error.message); }
});
