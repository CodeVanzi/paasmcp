import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { loadState, PAAS_DB_DIR, PAAS_REDIS_DIR, saveState } from "./config.js";
import { backupDatabase } from "./database.js";
import { audit } from "./guard.js";

// Every shared service runs a pinned image. `update check` looks for newer patch/minor releases of the
// same major; `update apply` backs up, switches, health-checks and rolls back on failure. A major jump
// (Postgres 16 → 17, Garage v1 → v2) changes data formats or APIs and is never done here.

export type Component = "postgres" | "redis" | "garage";

export const PINNED: Record<Component, string> = {
  postgres: "postgres:16.15-alpine",
  redis: "redis:7.4.12-alpine",
  garage: "dxflrs/garage:v1.3.1",
};

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";

const COMPOSE: Record<Component, () => string> = {
  postgres: () => path.join(PAAS_DB_DIR, "compose.yaml"),
  redis: () => path.join(PAAS_REDIS_DIR, "compose.yaml"),
  garage: () => path.join(path.dirname(PAAS_DB_DIR), "paasmcp-garage", "compose.yaml"),
};

/** The image a service runs: the one the updater recorded, else what an older install already runs, else the pin. */
export function imageFor(c: Component): string {
  const recorded = loadState().versions?.[c];
  if (recorded) return recorded;
  try {
    const repo = PINNED[c].split(":")[0];
    const m = fs.readFileSync(COMPOSE[c](), "utf-8").match(new RegExp(`image: (${repo.replace(/[/.]/g, "\\$&")}:[^\\s]+)`));
    if (m) return m[1];
  } catch {
    // not installed yet
  }
  return PINNED[c];
}

interface TagRule {
  repo: string; // Docker Hub repository path
  pattern: (major: string) => RegExp;
}

const RULES: Record<Component, TagRule> = {
  postgres: { repo: "library/postgres", pattern: (m) => new RegExp(`^${m}\\.(\\d+)-alpine$`) },
  redis: { repo: "library/redis", pattern: (m) => new RegExp(`^${m.replace(".", "\\.")}\\.(\\d+)-alpine$`) },
  garage: { repo: "dxflrs/garage", pattern: (m) => new RegExp(`^${m}\\.(\\d+)\\.(\\d+)$`) },
};

/** Major (or major.minor for Redis, whose minors change formats) that an update must keep. */
export function majorOf(c: Component, image: string): string {
  const tag = image.split(":")[1] || "";
  if (c === "postgres") return tag.split(".")[0].replace(/-alpine$/, "");
  if (c === "redis") return tag.split(".").slice(0, 2).join(".");
  return tag.split(".")[0]; // garage: "v1"
}

const numeric = (tag: string) => (tag.match(/\d+/g) || []).map(Number);
const newer = (a: string, b: string) => {
  const x = numeric(a);
  const y = numeric(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0);
  return false;
};

export function pickLatest(c: Component, current: string, tags: string[]): string | null {
  const re = RULES[c].pattern(majorOf(c, current));
  const currentTag = current.split(":")[1];
  const best = tags.filter((t) => re.test(t)).reduce<string | null>((acc, t) => (!acc || newer(t, acc) ? t : acc), null);
  return best && newer(best, currentTag) ? `${current.split(":")[0]}:${best}` : null;
}

async function hubTags(repo: string, prefix: string): Promise<string[]> {
  const url = `https://hub.docker.com/v2/repositories/${repo}/tags?page_size=100&name=${encodeURIComponent(prefix)}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
  if (!res.ok) throw new Error(`Docker Hub tags for ${repo}: HTTP ${res.status}`);
  return ((await res.json()) as { results: { name: string }[] }).results.map((r) => r.name);
}

export async function checkUpdates(fetchTags = hubTags): Promise<{ component: Component; running: string; available: string | null; note?: string }[]> {
  const out = [];
  for (const c of Object.keys(RULES) as Component[]) {
    const running = imageFor(c);
    try {
      const tags = await fetchTags(RULES[c].repo, majorOf(c, running) + ".");
      out.push({ component: c, running, available: pickLatest(c, running, tags) });
    } catch (err) {
      out.push({ component: c, running, available: null, note: err instanceof Error ? err.message : String(err) });
    }
  }
  return out;
}

interface Target {
  composeFile: string;
  container: string;
  health: () => boolean;
}

function run(args: string[]): string {
  return execFileSync("docker", args, { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
}

function targetsFor(c: Component): Target[] {
  const state = loadState();
  const pgReady = (container: string) => () => {
    try {
      run(["exec", container, "pg_isready", "-U", "paasmcp_admin", "-d", "postgres"]);
      return true;
    } catch {
      return false;
    }
  };
  if (c === "postgres") {
    // Copies of a peer first (they follow a newer primary fine, never the other way round), then our primary.
    const copies = Object.values(state.mirror?.replicas || {})
      .filter((r) => !r.failback)
      .map((r) => ({ composeFile: path.join(path.dirname(r.dataDir), "compose.yaml"), container: r.container, health: pgReady(r.container) }));
    return [...copies, { composeFile: COMPOSE.postgres(), container: "paasmcp-postgres", health: pgReady("paasmcp-postgres") }];
  }
  if (c === "redis") {
    return [
      {
        composeFile: COMPOSE.redis(),
        container: "paasmcp-redis",
        // A NOAUTH answer to an unauthenticated ping still proves the server is up.
        health: () => {
          try {
            return /PONG|NOAUTH/.test(run(["exec", "paasmcp-redis", "redis-cli", "ping"]));
          } catch {
            return false;
          }
        },
      },
    ];
  }
  return [
    {
      composeFile: COMPOSE.garage(),
      container: "paasmcp-garage",
      health: () => {
        try {
          return run(["inspect", "-f", "{{.State.Running}}", "paasmcp-garage"]).trim() === "true";
        } catch {
          return false;
        }
      },
    },
  ];
}

function swapImage(file: string, from: string, to: string): void {
  const text = fs.readFileSync(file, "utf-8");
  // Old installs used floating tags (postgres:16-alpine); match whatever image line the service has.
  const repo = from.split(":")[0];
  const next = text.replace(new RegExp(`image: ${repo.replace(/[/.]/g, "\\$&")}:[^\\s]+`), `image: ${to}`);
  fs.writeFileSync(file, next, { mode: 0o600 });
}

const waitHealthy = (t: Target, ms = 60_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (t.health()) return true;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  }
  return false;
};

export function applyUpdate(c: Component, toImage: string): {
  component: Component;
  from: string;
  to: string;
  updated: string[];
  safetyBackups: string[];
  rolledBack?: string;
} {
  const from = imageFor(c);
  if (toImage.split(":")[0] !== from.split(":")[0]) throw new Error(`'${toImage}' is not an image of ${c}.`);
  if (majorOf(c, toImage) !== majorOf(c, from)) {
    throw new Error(
      `${from} → ${toImage} is a major upgrade: data format or API changes. The updater only moves within ${majorOf(c, from)}; a major upgrade needs its own migration (dump and restore, or the project's upgrade guide).`
    );
  }
  const state = loadState();
  const safetyBackups: string[] = [];
  if (c === "postgres" && !OFFLINE()) {
    for (const db of Object.values(state.databases).filter((d) => d.engine === "postgres")) {
      safetyBackups.push(backupDatabase(db.appName, "postgres").id);
    }
  }
  const updated: string[] = [];
  if (!OFFLINE()) {
    try {
      run(["image", "inspect", toImage]);
    } catch {
      run(["pull", toImage]);
    }
    for (const t of targetsFor(c).filter((x) => fs.existsSync(x.composeFile))) {
      swapImage(t.composeFile, from, toImage);
      run(["compose", "-f", t.composeFile, "up", "-d"]);
      if (!waitHealthy(t)) {
        swapImage(t.composeFile, toImage, from);
        run(["compose", "-f", t.composeFile, "up", "-d"]);
        for (const done of updated) {
          const back = targetsFor(c).find((x) => x.container === done)!;
          swapImage(back.composeFile, toImage, from);
          run(["compose", "-f", back.composeFile, "up", "-d"]);
        }
        audit({ event: "update.rolled-back", component: c, from, to: toImage, failed: t.container });
        return { component: c, from, to: toImage, updated: [], safetyBackups, rolledBack: `${t.container} did not become healthy in 60 s; everything is back on ${from}.` };
      }
      updated.push(t.container);
    }
  }
  const s = loadState();
  s.versions = { ...(s.versions || {}), [c]: toImage };
  saveState(s);
  audit({ event: "update.applied", component: c, from, to: toImage, updated });
  return { component: c, from, to: toImage, updated, safetyBackups };
}
