import { execFile } from "node:child_process";
import { loadState } from "./config.js";
import { deployRuns } from "./deploys.js";
import { sendNotice } from "./notify.js";

// The dashboard runs all the time, so it also notices when an app stops on its own (a crash, the
// machine short of memory) and sends a notice, and another when it is back. Only inside the dashboard
// container (PAASMCP_IN_DASHBOARD=1) and only when notices are set up (Connections → Notices).

/** An app is reported down after this many rounds in a row, so a restart or a deploy swap is not a notice. */
export const DOWN_ROUNDS = 2;

export interface WatchEntry {
  /** Rounds in a row the app was seen not running. */
  misses: number;
  /** A "down" notice was sent and no "back" notice yet. */
  reported: boolean;
}

export type WatchEvent = { app: string; kind: "down" | "back" };

/**
 * One round, pure (tested): which apps should run, which run now, and which are mid-deploy.
 * An app mid-deploy keeps its count (the swap stops the old container for a moment).
 */
export function watchRound(
  prev: Map<string, WatchEntry> | undefined,
  expected: string[],
  running: Set<string>,
  busy: Set<string>
): { next: Map<string, WatchEntry>; events: WatchEvent[] } {
  const next = new Map<string, WatchEntry>();
  const events: WatchEvent[] = [];
  for (const app of expected) {
    const before = prev?.get(app);
    if (running.has(app)) {
      if (before?.reported) events.push({ app, kind: "back" });
      next.set(app, { misses: 0, reported: false });
      continue;
    }
    if (busy.has(app)) {
      next.set(app, before || { misses: 0, reported: false });
      continue;
    }
    const misses = (before?.misses || 0) + 1;
    const reported = Boolean(before?.reported) || misses >= DOWN_ROUNDS;
    if (reported && !before?.reported) events.push({ app, kind: "down" });
    next.set(app, { misses, reported });
  }
  return { next, events };
}

export function watchNoticeText(e: WatchEvent, lang: "pt" | "en"): { title: string; text: string } {
  if (lang === "en") {
    return e.kind === "down"
      ? { title: `${e.app} stopped`, text: `🔴 ${e.app} stopped running on its own. On the dashboard, open its Logs to see why, or Diagnostics.` }
      : { title: `${e.app} is back`, text: `🟢 ${e.app} is running again.` };
  }
  return e.kind === "down"
    ? { title: `${e.app} parou`, text: `🔴 ${e.app} parou de rodar sozinho. No painel, abra os Logs dele para ver o motivo, ou o Diagnóstico.` }
    : { title: `${e.app} voltou`, text: `🟢 ${e.app} está rodando de novo.` };
}

/** Apps that should be running here, by container name → app name. */
function expectedApps(): Map<string, string> {
  const state = loadState();
  const out = new Map<string, string>();
  // Same rules as a deploy (deployer.ts): a fenced server runs only apps it took over from a peer, and
  // apps whose data a later takeover moved elsewhere no longer run here. Those are stopped on purpose.
  const replicas = Object.values(state.mirror?.replicas || {});
  for (const a of Object.values(state.apps)) {
    if (!a || a.runtimeType === "paasmcp-control-plane" || a.trashedAt) continue;
    if (state.mirror?.fenced && !a.originNodeId) continue;
    if (a.originNodeId && replicas.some((r) => r.peerNodeId === a.originNodeId && r.promotedAt && r.supersededBy && !r.handedBackAt)) continue;
    if (a.status === "stopped" || a.status === "trashed") continue;
    if (!a.containerName) continue;
    out.set(a.containerName, a.name);
  }
  return out;
}

function deploying(app: string): boolean {
  try {
    return deployRuns(app).some((r) => !r.finishedAt && r.phase !== "failed" && r.phase !== "live");
  } catch {
    return false;
  }
}

export function startAppWatch(): () => void {
  if (process.env.PAASMCP_IN_DASHBOARD !== "1" || process.env.PAASMCP_APP_WATCH === "0") return () => {};
  let prev: Map<string, WatchEntry> | undefined;
  let running = false;
  const round = () => {
    if (running) return;
    running = true;
    execFile("docker", ["ps", "--format", "{{.Names}}"], { timeout: 30_000 }, (err, stdout) => {
      running = false;
      if (err) return; // Docker busy or restarting: try again next round, without guessing.
      const byContainer = expectedApps();
      const up = new Set(stdout.split("\n").map((s) => s.trim()).filter(Boolean));
      const expected = [...byContainer.values()];
      const runningApps = new Set([...byContainer].filter(([c]) => up.has(c)).map(([, app]) => app));
      const busy = new Set(expected.filter(deploying));
      const { next, events } = watchRound(prev, expected, runningApps, busy);
      prev = next;
      for (const e of events) void sendNotice((lang) => watchNoticeText(e, lang), `app.${e.kind}`, e.app);
    });
  };
  const first = setTimeout(round, 30_000);
  const timer = setInterval(round, 60_000);
  first.unref();
  timer.unref();
  return () => {
    clearTimeout(first);
    clearInterval(timer);
  };
}
