// Loaded as an external module because the CSP (phase "standards") forbids inline scripts.
const out = document.getElementById("health");

try {
  const res = await fetch("/api/health", { cache: "no-store" });
  const text = await res.text();
  out.textContent = `HTTP ${res.status}\n${text}`;
} catch (err) {
  out.textContent = `request failed: ${err}`;
}
