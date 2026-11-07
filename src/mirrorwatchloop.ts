import { execFile } from "node:child_process";
import path from "node:path";
import { loadState } from "./config.js";

// The dashboard container runs continuously, so it acts as the automatic watchdog for two-server
// mirroring: every 15 seconds it executes a single watch round ('paasmcp mirror watch --once')
// whenever an arbiter or mirror is configured. This eliminates the need to manually install or run
// a host systemd service ('sudo paasmcp mirror install-watch') for standard deployments.

export function watchIntervalSeconds(): number {
  const n = Number(process.env.PAASMCP_MIRROR_WATCH_SECONDS || 15);
  return Number.isFinite(n) && n >= 5 ? n : 15;
}

export function startMirrorWatchLoop(): () => void {
  if (process.env.PAASMCP_IN_DASHBOARD !== "1" || process.env.PAASMCP_DASHBOARD_WATCH === "0") return () => {};
  const cli = path.join(path.dirname(new URL(import.meta.url).pathname), "cli.js");
  let running = false;

  const round = () => {
    if (running) return;
    const state = loadState();
    // Only run if an arbiter or a replica is present on this server
    if (!state.mirror?.arbiterUrl && !Object.keys(state.mirror?.replicas || {}).length) return;

    running = true;
    execFile(
      process.execPath,
      [cli, "mirror", "watch", "--once"],
      { timeout: 30_000, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout, stderr) => {
        running = false;
        if (err) {
          const msg = String(stderr || err.message).trim().split("\n").slice(-2).join(" ");
          // Skip logging if just unreachable briefly
          if (msg && !msg.includes("skipped")) {
            console.error(`[mirror-watch] ${msg.slice(0, 200)}`);
          }
          return;
        }
        const out = stdout.trim();
        if (out && (out.includes("fenced") || out.includes("promoted") || out.includes("activeSync"))) {
          console.log(`[mirror-watch] ${out.replace(/\s+/g, " ").slice(0, 1000)}`);
        }
      }
    );
  };

  const first = setTimeout(round, 5000);
  const timer = setInterval(round, watchIntervalSeconds() * 1000);
  first.unref();
  timer.unref();
  return () => {
    clearTimeout(first);
    clearInterval(timer);
  };
}
