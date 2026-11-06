import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { ensureDataDir, PAAS_DATA_DIR, writeFileAtomic } from "./config.js";

// The nightly backup used to run only from a systemd timer that someone had to install in a terminal
// (`paasmcp backup install-timer`), so a dashboard-only install never made a backup on its own. The
// dashboard runs all the time, so it now starts `paasmcp backup nightly --if-due` itself once a day.
// Every nightly run writes a mark first, so a systemd timer and the dashboard never both run the same day.

export const NIGHTLY_MARK = path.join(PAAS_DATA_DIR, "backups-nightly.json");
/** Local hour (server time) from which the day's backup is due. */
export const NIGHTLY_HOUR = 3;
/** The dashboard waits until hh:30, after a systemd timer's 3:00 + up to 15 min random delay has started. */
const DASHBOARD_MINUTE = 30;

export interface NightlyMark {
  /** Local date (YYYY-MM-DD) of the last run that started. */
  date: string;
  startedAt: string;
  finishedAt?: string;
  created?: number;
  errors?: string[];
  offsite?: string;
}

export function localDate(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

export function readNightlyMark(): NightlyMark | undefined {
  try {
    const m = JSON.parse(fs.readFileSync(NIGHTLY_MARK, "utf-8")) as NightlyMark;
    return typeof m.date === "string" ? m : undefined;
  } catch {
    return undefined;
  }
}

export function writeNightlyMark(m: NightlyMark): void {
  ensureDataDir(path.dirname(NIGHTLY_MARK));
  writeFileAtomic(NIGHTLY_MARK, JSON.stringify(m, null, 2));
}

/** Pure (tested): is today's backup due at `now`, given the last run's local date? */
export function nightlyDue(now: Date, lastDate: string | undefined, minute = 0, hour = NIGHTLY_HOUR): boolean {
  if (lastDate === localDate(now)) return false;
  return now.getHours() > hour || (now.getHours() === hour && now.getMinutes() >= minute);
}

/** Dashboard container only: checks every 10 minutes and starts the nightly run in its own process. */
export function startNightlyLoop(): () => void {
  if (process.env.PAASMCP_IN_DASHBOARD !== "1" || process.env.PAASMCP_DASHBOARD_BACKUP === "0") return () => {};
  const cli = path.join(path.dirname(new URL(import.meta.url).pathname), "cli.js");
  let running = false;
  const tick = () => {
    if (running || !nightlyDue(new Date(), readNightlyMark()?.date, DASHBOARD_MINUTE)) return;
    running = true;
    execFile(process.execPath, [cli, "backup", "nightly", "--if-due"], { timeout: 3 * 60 * 60 * 1000, maxBuffer: 16 * 1024 * 1024 }, (err, _stdout, stderr) => {
      running = false;
      if (err) console.error(`[backup] ${String(stderr || err.message).trim().split("\n").slice(-3).join(" | ")}`);
    });
  };
  const first = setTimeout(tick, 90_000);
  const timer = setInterval(tick, 10 * 60 * 1000);
  first.unref();
  timer.unref();
  return () => {
    clearTimeout(first);
    clearInterval(timer);
  };
}
