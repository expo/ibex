const esc = (s) => String(s).replace(/[^\x20-\x7e]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
const checks = [
  ["typeof Intl", () => typeof Intl],
  ["(1234.5).toLocaleString('de-DE')", () => (1234.5).toLocaleString("de-DE")],
  ["NumberFormat en-US USD 12.5", () => new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(12.5)],
  ["DateTimeFormat en-US medium UTC Date(0)", () => new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeZone: "UTC" }).format(new Date(0))],
  ["'i'.toLocaleUpperCase('tr')", () => "i".toLocaleUpperCase("tr")],
  ["'é'.toUpperCase()", () => "é".toUpperCase()],
  ["'ß'.toUpperCase()", () => "ß".toUpperCase()],
  ["formatToParts de-DE -1234.5", () => JSON.stringify(new Intl.NumberFormat("de-DE").formatToParts(-1234.5))],
  ["NumberFormat ja-JP JPY", () => new Intl.NumberFormat("ja-JP", { style: "currency", currency: "JPY" }).format(1234.5)],
  ["NumberFormat en-IN", () => new Intl.NumberFormat("en-IN").format(1234567.891)],
  ["NumberFormat compact", () => new Intl.NumberFormat("en", { notation: "compact" }).format(1234567)],
  ["NumberFormat percent", () => new Intl.NumberFormat("en", { style: "percent", maximumFractionDigits: 1 }).format(0.1234)],
  ["NumberFormat unit", () => new Intl.NumberFormat("en", { style: "unit", unit: "kilometer-per-hour" }).format(50)],
  ["NumberFormat resolved default locale", () => new Intl.NumberFormat().resolvedOptions().locale],
  ["DateTimeFormat resolved default", () => JSON.stringify(new Intl.DateTimeFormat().resolvedOptions())],
  ["DateTimeFormat en-US full UTC", () => new Intl.DateTimeFormat("en-US", { dateStyle: "full", timeStyle: "long", timeZone: "UTC" }).format(new Date(0))],
  ["DateTimeFormat formatToParts", () => JSON.stringify(new Intl.DateTimeFormat("en-US", { hour: "numeric", minute: "2-digit", timeZone: "UTC" }).formatToParts(new Date(0)))],
  ["DateTimeFormat de-DE Berlin", () => new Intl.DateTimeFormat("de-DE", { year: "numeric", month: "long", day: "numeric", hour: "numeric", minute: "numeric", timeZone: "Europe/Berlin" }).format(new Date(0))],
  ["DateTimeFormat th-TH calendar", () => new Intl.DateTimeFormat("th-TH").resolvedOptions().calendar],
  ["timeZone asia/calcutta", () => new Intl.DateTimeFormat("en", { timeZone: "asia/calcutta" }).resolvedOptions().timeZone],
  ["Date#toLocaleString en-US UTC", () => new Date(0).toLocaleString("en-US", { timeZone: "UTC" })],
  ["Date#toLocaleDateString de-DE", () => new Date(0).toLocaleDateString("de-DE", { timeZone: "UTC" })],
  ["Date#toLocaleTimeString en-US UTC", () => new Date(0).toLocaleTimeString("en-US", { timeZone: "UTC" })],
  ["Intl.getCanonicalLocales", () => typeof Intl.getCanonicalLocales === "function" ? JSON.stringify(Intl.getCanonicalLocales(["EN-us"])) : "n/a"],
  ["'I'.toLocaleLowerCase('tr')", () => "I".toLocaleLowerCase("tr")],
  ["'İ'.toLocaleLowerCase('en')", () => "İ".toLocaleLowerCase("en")],
  ["localeCompare", () => ["b", "a", "á"].sort((x, y) => x.localeCompare(y)).join(",")],
  ["'é'.normalize('NFD').length", () => "é".normalize("NFD").length],
  ["Object.keys(Intl)", () => typeof Intl === "object" ? Object.getOwnPropertyNames(Intl).join(",") : "n/a"],
];
for (const [label, fn] of checks) {
  let v;
  try { v = fn(); } catch (e) { v = "THROWS " + (e && e.name) + ": " + (e && e.message); }
  console.log(label + " => " + esc(v));
}
