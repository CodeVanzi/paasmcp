import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { ensureDataDir, PAAS_DATA_DIR } from "./config.js";

// Ready-made apps for the dashboard (like Coolify services or CapRover one-click apps), for people
// who want something running without a repository. Each one is a small docker-compose file written
// here and published like any local folder, so it goes through the same sanitizing, vault and
// loopback-only port as every other app. Images are pinned (exact tag, multi-arch incl. arm64).

export interface AppTemplate {
  id: string;
  image: string;
  /** Port the app listens on inside its container. */
  port: number;
  /** Where the app keeps its data inside the container (a named volume, kept across publishes). */
  dataPath?: string;
  /** The first person to open it creates the admin account: say so before it gets a public address. */
  firstVisitAdmin: boolean;
  homepage: string;
}

export const TEMPLATES: readonly AppTemplate[] = [
  {
    id: "uptime-kuma",
    image: "louislam/uptime-kuma:2.5.6",
    port: 3001,
    dataPath: "/app/data",
    firstVisitAdmin: true,
    homepage: "https://github.com/louislam/uptime-kuma",
  },
  {
    id: "memos",
    image: "neosmemo/memos:0.31.0",
    port: 5230,
    dataPath: "/var/opt/memos",
    firstVisitAdmin: true,
    homepage: "https://github.com/usememos/memos",
  },
  {
    id: "it-tools",
    image: "corentinth/it-tools:2024.10.22-7ca5933",
    port: 80,
    firstVisitAdmin: false,
    homepage: "https://github.com/CorentinTh/it-tools",
  },
];

export const TEMPLATES_DIR = path.join(PAAS_DATA_DIR, "templates");

export function findTemplate(id: string): AppTemplate {
  const t = TEMPLATES.find((x) => x.id === id);
  if (!t) throw new Error(`Unknown ready-made app '${id}'. Available: ${TEMPLATES.map((x) => x.id).join(", ")}.`);
  return t;
}

/** The compose file for one template (pure, tested). */
export function templateCompose(t: AppTemplate): string {
  const app: Record<string, unknown> = { image: t.image, ports: [String(t.port)] };
  const doc: Record<string, unknown> = { services: { app } };
  if (t.dataPath) {
    app.volumes = [`data:${t.dataPath}`];
    doc.volumes = { data: {} };
  }
  return YAML.stringify(doc);
}

/** Writes the template's folder and returns it, ready to be published as a local source. */
export function prepareTemplate(id: string): { dir: string; template: AppTemplate } {
  const template = findTemplate(id);
  ensureDataDir(TEMPLATES_DIR);
  const dir = path.join(TEMPLATES_DIR, template.id);
  ensureDataDir(dir);
  fs.writeFileSync(path.join(dir, "docker-compose.yml"), templateCompose(template), { mode: 0o600 });
  return { dir, template };
}
