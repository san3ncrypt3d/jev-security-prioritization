// Render a recorded real-PTY session (.cast) with xterm.js in headless Chrome.
//
//   node render.mjs <cast> <out.png> [--title T] [--until TEXT] [--nth N] [--max-rows R]
//
// The byte stream is written verbatim into an xterm.js terminal (the terminal
// emulator used by VS Code). --until cuts the stream right after the N-th
// event containing TEXT, i.e. the screen exactly as it looked at that moment
// of the real session. If output exceeds the window height the terminal
// scrolls, as a real one would.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import puppeteer from "puppeteer-core";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const [castPath, outPath] = args;
const lines = fs.readFileSync(castPath, "utf8").trim().split("\n");
const header = JSON.parse(lines[0]);
let events = lines.slice(1).map((l) => JSON.parse(l));
const until = opt("--until", null);
if (until) {
  let n = parseInt(opt("--nth", "1"), 10);
  const idx = events.findIndex((e) => e[2].includes(until) && --n === 0);
  if (idx < 0) throw new Error(`--until text not found: ${until}`);
  events = events.slice(0, idx + 1);
}
const data = events.map((e) => e[2]).join("");
const cols = header.width;
const maxRows = parseInt(opt("--max-rows", String(header.height)), 10);
const title = opt("--title", "~/openrouter");

const html = `<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="${pathToFileURL(path.join(here, "node_modules/@xterm/xterm/css/xterm.css"))}">
<script src="${pathToFileURL(path.join(here, "node_modules/@xterm/xterm/lib/xterm.js"))}"></script>
<style>
 body{margin:0;background:transparent;font-family:'Ubuntu Sans','Cantarell','DejaVu Sans',sans-serif}
 #win{display:inline-block;border-radius:12px;overflow:hidden;background:#1e1e1e;
      box-shadow:0 0 0 1px rgba(0,0,0,.35)}
 #bar{height:38px;background:#2b2b2b;color:#eeeeec;display:flex;align-items:center;justify-content:center;
      position:relative;font-size:14px;font-weight:600}
 #bar .btns{position:absolute;right:12px;display:flex;gap:10px}
 #bar .btns span{width:14px;height:14px;border-radius:50%;background:#474747;display:inline-block}
 #term{padding:6px 8px 8px 8px}
 .xterm-viewport{overflow:hidden!important}
</style></head><body><div id="win"><div id="bar">${title.replace(/</g, "&lt;")}
<div class="btns"><span></span><span></span><span></span></div></div><div id="term"></div></div></body></html>`;
const tmp = path.join(here, ".render.html");
fs.writeFileSync(tmp, html);

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME || "/usr/bin/google-chrome",
  headless: true,
  args: ["--no-sandbox", "--allow-file-access-from-files"],
});
const page = await browser.newPage();
await page.setViewport({ width: 2400, height: 2400, deviceScaleFactor: 2 });
await page.goto(pathToFileURL(tmp).href);
await page.evaluate(async (data, cols, maxRows) => {
  await document.fonts.ready;
  const term = new Terminal({
    cols, rows: maxRows, fontFamily: "'Ubuntu Sans Mono','Ubuntu Mono','DejaVu Sans Mono',monospace",
    fontSize: 15, lineHeight: 1.12, cursorBlink: false, allowProposedApi: true, scrollback: 10000,
    theme: {
      background: "#1e1e1e", foreground: "#d4d4d4", cursor: "#d4d4d4",
      black: "#1e1e1e", red: "#f66151", green: "#57e389", yellow: "#f8e45c", blue: "#62a0ea",
      magenta: "#c061cb", cyan: "#5bc8af", white: "#d4d4d4", brightBlack: "#77767b",
      brightRed: "#ff7b63", brightGreen: "#8ff0a4", brightYellow: "#f9f06b", brightBlue: "#8cb8ff",
      brightMagenta: "#dc8add", brightCyan: "#93ddc2", brightWhite: "#ffffff",
    },
  });
  term.open(document.getElementById("term"));
  await new Promise((r) => term.write(data, r));
  // Shrink the window to the used height (like a snug terminal window); keep scroll if overflowing.
  const buf = term.buffer.active;
  let last = 0;
  for (let i = 0; i < buf.length; i++) if (buf.getLine(i).translateToString(true).trim()) last = i;
  const used = Math.min(maxRows, last + 1 - buf.viewportY);
  if (buf.length <= maxRows) term.resize(cols, Math.max(used, 3));
  await new Promise((r) => setTimeout(r, 200));
}, data, cols, maxRows);
const el = await page.$("#win");
await el.screenshot({ path: outPath, omitBackground: true });
await browser.close();
fs.unlinkSync(tmp);
console.log(`wrote ${outPath}`);
