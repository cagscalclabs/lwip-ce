import { ESPLoader, Transport } from "https://cdn.jsdelivr.net/npm/esptool-js@0.7.0/bundle.js";

const boards = [
  { name: "lwIP-CE bridge board (ESP32-S3-WROOM-1-N16R8)", chip: "ESP32-S3", flash: "16MB" },
];
const minimumVersion = [3, 0, 0];
const securityNames = ["Open", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3", "Enterprise"];
const SEC_OPEN = 0;
const SEC_WEP = 1;
const SEC_WPA3 = 4;
const SEC_ENTERPRISE = 6;
const FLAG_HIDDEN = 0x02;
const FLAG_ACTIVE = 0x04;
const FLAG_CHECK_SERVER = 0x08;
const reasons = [
  "",
  "The network is not in range.",
  "The password or credentials are wrong.",
  "The signal was lost.",
  "The network turned the bridge away.",
  "The bridge could not join the network.",
];
const errors = {
  busy: "The bridge is busy joining a network. Try again in a moment.",
  full: "The bridge already holds 8 networks. Forget one first.",
  "bad-request": "The bridge rejected the request.",
  "not-found": "That network is no longer saved.",
};

const $ = (id) => document.getElementById(id);
const release = $("fw-release");
const board = $("fw-board");
const baud = $("fw-baud");
const flashButton = $("fw-flash");
const flashStatus = $("fw-status");
const progress = $("fw-progress");
const log = $("fw-log");
const details = $("fw-details");
const connectButton = $("wifi-connect");
const wifiStatus = $("wifi-status");
const panel = $("wifi-panel");
const saved = $("wifi-saved");
const form = $("wifi-form");
const scanButton = $("wifi-scan");
const nearby = $("wifi-nearby");
const ssid = $("wifi-ssid");
const security = $("wifi-security");
const username = $("wifi-username");
const password = $("wifi-password");
const show = $("wifi-show");
const hidden = $("wifi-hidden");
const check = $("wifi-check");
const result = $("wifi-result");

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const bridge = { port: undefined, reader: undefined, writer: undefined, loop: undefined, waiter: undefined };
let queue = Promise.resolve();
let polling = 0;
let busy = false;
let scanned = [];

const terminal = {
  clean() {
    log.textContent = "";
  },
  write(text) {
    log.textContent += text;
    log.scrollTop = log.scrollHeight;
  },
  writeLine(line) {
    this.write(line + "\n");
  },
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const bytes = (text) => encoder.encode(text).length;
const toHex = (text) => Array.from(encoder.encode(text), (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (hex) => decoder.decode(new Uint8Array((hex.match(/../g) ?? []).map((b) => parseInt(b, 16))));

function newer(version, minimum) {
  const parts = version.match(/^v?(\d+)\.(\d+)\.(\d+)/)?.slice(1).map(Number);
  if (!parts) return false;
  for (let i = 0; i < 3; i++) {
    if (parts[i] !== minimum[i]) return parts[i] > minimum[i];
  }
  return true;
}

function say(element, text, kind = "") {
  element.textContent = text;
  element.className = kind ? `tool-status ${kind}` : "tool-status";
}

function report(element, e) {
  say(element, e?.message ?? String(e), "error");
  terminal.writeLine(element.textContent);
  details.open = true;
}

function update() {
  const connected = bridge.writer !== undefined;
  flashButton.disabled = busy || !release.options.length;
  connectButton.disabled = busy;
  connectButton.textContent = connected ? "Disconnect" : "Connect";
  panel.disabled = busy || !connected || !bridge.version;
}

function updateFields() {
  const sec = Number(security.value);
  $("wifi-username-row").hidden = sec !== SEC_ENTERPRISE;
  $("wifi-check-row").hidden = sec !== SEC_ENTERPRISE;
  $("wifi-password-row").hidden = sec === SEC_OPEN;
  username.required = sec === SEC_ENTERPRISE;
  password.required = sec !== SEC_OPEN;
}

function passwordProblem(sec, text) {
  const length = bytes(text);
  const isHex = /^[0-9a-fA-F]*$/.test(text);
  if (sec === SEC_OPEN) return null;
  if (sec === SEC_WEP) {
    return [5, 13].includes(length) || (isHex && [10, 26].includes(length))
      ? null
      : "A WEP key is 5 or 13 characters, or 10 or 26 hex digits.";
  }
  if (sec === SEC_ENTERPRISE || sec === SEC_WPA3) {
    return length >= 1 && length <= 64 ? null : "The password must be 1 to 64 bytes.";
  }
  return (length >= 8 && length <= 63) || (isHex && length === 64)
    ? null
    : "A WPA password is 8 to 63 characters, or 64 hex digits.";
}

async function readLoop(reader) {
  let buffer = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      const text = decoder.decode(value, { stream: true });
      terminal.write(text);
      buffer += text;
      let end;
      while ((end = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, end).replace(/\r$/, "");
        buffer = buffer.slice(end + 1);
        bridge.waiter?.(line);
      }
    }
  } catch {
  } finally {
    reader.releaseLock();
    bridge.waiter?.(null);
  }
}

function send(name, args, timeout) {
  return new Promise((resolve, reject) => {
    const rows = [];
    const timer = setTimeout(() => finish(new Error("The bridge did not answer.")), timeout);
    function finish(error) {
      clearTimeout(timer);
      bridge.waiter = undefined;
      if (error) reject(error);
      else resolve(rows);
    }
    bridge.waiter = (line) => {
      if (line === null) return finish(new Error("The bridge was disconnected."));
      if (!line.startsWith(`@${name} `)) return;
      const fields = line.split(" ").slice(1);
      if (fields[0] === "ok") finish();
      else if (fields[0] === "error") finish(new Error(errors[fields[1]] ?? `The bridge answered: ${fields[1]}.`));
      else rows.push(fields);
    };
    if (!bridge.writer) return finish(new Error("The bridge is not connected."));
    bridge.writer.write(encoder.encode(args.length ? `${name} ${args.join(" ")}\n` : `${name}\n`)).catch(finish);
  });
}

function command(name, args = [], timeout = 3000) {
  const run = queue.then(() => send(name, args, timeout));
  queue = run.catch(() => {});
  return run;
}

async function openBridge() {
  bridge.port ??= await navigator.serial.requestPort();
  await bridge.port.open({ baudRate: 115200 });
  await bridge.port.setSignals({ dataTerminalReady: false });
  await bridge.port.setSignals({ requestToSend: false });
  bridge.writer = bridge.port.writable.getWriter();
  bridge.reader = bridge.port.readable.getReader();
  bridge.loop = readLoop(bridge.reader);
  bridge.loop.then(closeBridge);
  update();
}

async function closeBridge() {
  if (!bridge.writer) return;
  const { port, reader, writer, loop } = bridge;
  bridge.writer = bridge.reader = bridge.version = undefined;
  await reader.cancel().catch(() => {});
  await loop;
  writer.releaseLock();
  await port.close().catch(() => {});
  say(wifiStatus, "Not connected to the bridge.");
  update();
}

async function connectBridge() {
  say(wifiStatus, "Connecting to the bridge…");
  await openBridge();
  let version;
  const deadline = Date.now() + 15000;
  while (!version && bridge.writer && Date.now() < deadline) {
    version = await command("bridge-version", [], 1500).then((rows) => rows[0]?.[0], () => undefined);
  }
  if (!version) {
    await closeBridge();
    throw new Error("The bridge did not answer. Flash firmware 3.0.0 or newer above, then connect again.");
  }
  if (!newer(version, minimumVersion)) {
    await closeBridge();
    throw new Error(`The bridge runs firmware ${version}. Flash 3.0.0 or newer above, then connect again.`);
  }
  bridge.version = version;
  update();
  await refreshSaved();
  await refreshStatus();
  poll();
}

async function poll() {
  const id = ++polling;
  while (bridge.version && id === polling) {
    await sleep(3000);
    if (!busy) await refreshStatus().catch(() => {});
  }
}

async function readStatus() {
  const [state, reason, rssi, name] = (await command("wifi-status"))[0];
  return { state, reason: Number(reason), rssi: Number(rssi), ssid: fromHex(name ?? "") };
}

async function refreshStatus() {
  const status = await readStatus();
  const prefix = `Bridge firmware ${bridge.version}. `;
  if (status.state === "connected") {
    say(wifiStatus, `${prefix}On ${status.ssid} (${status.rssi} dBm).`, "ok");
  } else if (status.state === "joining") {
    say(wifiStatus, `${prefix}Joining a network…`);
  } else {
    say(wifiStatus, `${prefix}Not on Wi-Fi. ${reasons[status.reason] ?? ""}`.trim());
  }
  return status;
}

async function refreshSaved() {
  const rows = await command("wifi-list");
  saved.replaceChildren();
  if (!rows.length) {
    const cell = saved.insertRow().insertCell();
    cell.textContent = "No saved networks.";
    return;
  }
  for (const [slot, flags, sec, name] of rows) {
    const row = saved.insertRow();
    const notes = [securityNames[sec] ?? "?"];
    if (flags & FLAG_HIDDEN) notes.push("hidden");
    if (flags & FLAG_ACTIVE) notes.push("in use");
    row.insertCell().textContent = fromHex(name);
    row.insertCell().textContent = notes.join(", ");
    const forget = document.createElement("button");
    forget.type = "button";
    forget.className = "btn btn-neutral";
    forget.textContent = "Forget";
    forget.addEventListener("click", () => run(result, async () => {
      await command("wifi-forget", [slot]);
      say(result, `Forgot ${fromHex(name)}.`);
      await refreshSaved();
    }));
    row.insertCell().append(forget);
  }
}

async function run(status, task) {
  busy = true;
  update();
  try {
    await task();
  } catch (e) {
    report(status, e);
  } finally {
    busy = false;
    update();
  }
}

async function waitForJoin(name) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    await sleep(1000);
    const status = await refreshStatus();
    if (status.state === "connected" && status.ssid === name) return say(result, `Connected to ${name} (${status.rssi} dBm).`, "ok");
    if (status.state === "idle" && status.reason) {
      throw new Error(`Could not join ${name}. ${reasons[status.reason] ?? ""} The network stays saved; the bridge tries again every 15 seconds.`);
    }
  }
  say(result, `Saved ${name}. The bridge has not joined it yet and keeps trying every 15 seconds.`);
}

for (const b of boards) board.add(new Option(b.name));
const releases = await fetch("firmware/releases.json")
  .then((r) => (r.ok ? r.json() : []))
  .catch(() => []);
for (const r of releases) release.add(new Option(r.prerelease ? `${r.tag} (pre-release)` : r.tag, r.file));

updateFields();
if (!("serial" in navigator)) {
  const message = "This browser has no Web Serial. Use Chrome, Edge or Opera on desktop.";
  say(flashStatus, message, "error");
  say(wifiStatus, message, "error");
} else {
  if (!releases.length) say(flashStatus, "No firmware releases found.", "error");
  update();
}

flashButton.addEventListener("click", () => run(flashStatus, async () => {
  const target = boards[board.selectedIndex];
  let transport;
  progress.value = 0;
  progress.hidden = false;
  terminal.clean();
  say(flashStatus, "Flashing…");
  await closeBridge();
  try {
    bridge.port = await navigator.serial.requestPort();
    const response = await fetch("firmware/" + release.value);
    if (!response.ok) throw new Error(`Could not download ${release.value} (HTTP ${response.status}).`);
    const data = new Uint8Array(await response.arrayBuffer());

    transport = new Transport(bridge.port);
    const loader = new ESPLoader({ transport, baudrate: Number(baud.value), terminal });
    await loader.main();
    if (loader.chip.CHIP_NAME !== target.chip) {
      throw new Error(`Found an ${loader.chip.CHIP_NAME}, but this board has an ${target.chip}.`);
    }
    const flash = await loader.detectFlashSize();
    if (flash !== target.flash) {
      throw new Error(`Found ${flash ?? "an unknown size of"} flash, but this board has ${target.flash}.`);
    }

    await loader.writeFlash({
      fileArray: [{ data, address: 0 }],
      flashMode: "keep",
      flashFreq: "keep",
      flashSize: "keep",
      eraseAll: false,
      compress: true,
      reportProgress: (_, written, total) => {
        progress.value = written / total;
      },
    });
    await loader.after();
  } finally {
    await transport?.disconnect().catch(() => {});
  }
  say(flashStatus, "Done. The bridge is restarting.", "ok");
  terminal.writeLine(flashStatus.textContent);
  $("wifi").scrollIntoView({ behavior: "smooth" });
  try {
    await connectBridge();
  } catch (e) {
    report(wifiStatus, e);
  }
}));

connectButton.addEventListener("click", () => run(wifiStatus, async () => {
  if (bridge.writer) {
    await closeBridge();
  } else {
    try {
      await connectBridge();
    } catch (e) {
      if (e?.name === "NetworkError") bridge.port = undefined;
      throw e;
    }
  }
}));

scanButton.addEventListener("click", () => run(result, async () => {
  say(result, "Scanning…");
  scanned = (await command("wifi-scan", [], 15000)).map(([rssi, channel, sec, name]) => ({
    ssid: fromHex(name),
    rssi: Number(rssi),
    channel: Number(channel),
    security: Number(sec),
  }));
  nearby.replaceChildren(new Option(scanned.length ? "Choose a network" : "No networks found", ""));
  scanned.forEach((n, i) => {
    nearby.add(new Option(`${n.ssid} (${n.rssi} dBm, ${securityNames[n.security] ?? "?"})`, String(i)));
  });
  say(result, "");
}));

nearby.addEventListener("change", () => {
  const network = scanned[Number(nearby.value)];
  if (!nearby.value || !network) return;
  ssid.value = network.ssid;
  security.value = String(network.security);
  hidden.checked = false;
  updateFields();
  (network.security === SEC_ENTERPRISE ? username : password).focus();
});

security.addEventListener("change", updateFields);
show.addEventListener("change", () => {
  password.type = show.checked ? "text" : "password";
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const sec = Number(security.value);
  const name = ssid.value;
  const secret = sec === SEC_OPEN ? "" : password.value;
  const user = sec === SEC_ENTERPRISE ? username.value : "";
  const problem =
    (bytes(name) > 32 && "The network name is longer than 32 bytes.") ||
    (bytes(user) > 64 && "The username is longer than 64 bytes.") ||
    passwordProblem(sec, secret);
  if (problem) {
    say(result, problem, "error");
    return;
  }
  let flags = hidden.checked ? FLAG_HIDDEN : 0;
  if (sec === SEC_ENTERPRISE && check.checked) flags |= FLAG_CHECK_SERVER;

  run(result, async () => {
    say(result, `Saving ${name}…`);
    await command("wifi-add", [sec, flags, toHex(name), toHex(secret), toHex(user)]);
    password.value = "";
    await refreshSaved();
    say(result, `Joining ${name}…`);
    await waitForJoin(name);
    await refreshSaved();
  });
});
