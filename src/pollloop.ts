import { execFile } from "node:child_process";
import path from "node:path";

// The dashboard runs all the time, so it is the scheduler for auto-deploy: every couple of minutes it
// starts `paasmcp poll run` as a separate process (same lock, same rules as the systemd timer, and a
// crash in a round never takes the dashboard down). Only inside the dashboard container
// (PAASMCP_IN_DASHBOARD=1); a systemd timer, if installed too, simply finds nothing new.

export function pollIntervalSeconds(): number {
  const n = Number(process.env.PAASMCP_POLL_SECONDS || 120);
  return Number.isFinite(n) && n >= 30 ? n : 120;
}

export function startPollLoop(): () => void {
  if (process.env.PAASMCP_IN_DASHBOARD !== "1" || process.env.PAASMCP_DASHBOARD_POLL === "0") return () => {};
  const cli = path.join(path.dirname(new URL(import.meta.url).pathname), "cli.js");
  let running = false;
  const round = () => {
    if (running) return;
    running = true;
    execFile(process.execPath, [cli, "poll", "run"], { timeout: 45 * 60 * 1000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      running = false;
      if (err) {
        console.error(`[poll] ${String(stderr || err.message).trim().split("\n").slice(-3).join(" | ")}`);
        return;
      }
      const out = stdout.trim();
      if (/"deployed":\s*\[\s*\{|"status":\s*"(updated|swapping|failed)"|"errors":\s*\[\s*\{/.test(out)) console.log(`[poll] ${out.replace(/\s+/g, " ").slice(0, 2000)}`);
    });
  };
  const first = setTimeout(round, 60_000);
  const timer = setInterval(round, pollIntervalSeconds() * 1000);
  first.unref();
  timer.unref();
  return () => {
    clearTimeout(first);
    clearInterval(timer);
  };
}
