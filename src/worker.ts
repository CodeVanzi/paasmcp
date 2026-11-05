#!/usr/bin/env node
import { execFileSync, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildRunArgs,
  COPY_CONTAINER_PREFIX,
  CopySpec,
  helloProof,
  imageFingerprint,
  normalizeArch,
  parseOrder,
  POOL_IMAGE_REPO,
  renderEnvFile,
  validateCopySpec,
  validateIpv4,
  WORKER_HOME,
  WORKER_RUN_DIR,
  WorkerCopy,
  WorkerFacts,
} from "./poolproto.js";

// The helper side of the pool, run by sshd as the forced command of the origin's key
// (authorized_keys of the paasmcp-worker user: from=<origin IP>, command=<this file>, restrict).
// One order per connection, read from SSH_ORIGINAL_COMMAND and checked against a fixed list; JSON in on
// stdin, JSON out on stdout. It never runs a shell for the caller and nothing stays running between
// orders: the helper keeps 0 MB of PaaSMCP in memory while idle.
//
// An app's variables are written only to a tmpfs folder (/run/paasmcp-worker), mounted read-only into
// the copy and loaded by a small wrapper, so they are not in the container's config on disk nor in
// `docker inspect`. They are deleted when the copy stops, and vanish on reboot.

const TMPFS_MAGIC = 0x01021994;
const MAX_JSON_INPUT = 1024 * 1024;
const LOG_MAX_BYTES = 1024 * 1024;

export interface WorkerConfig {
  v: 1;
  name: string;
  originNodeId: string;
  originName: string;
  originIp: string;
  inviteId: string;
  /** Present until the first `hello`, then deleted (the invite proves itself once). */
  proofKey?: string;
  give: { cpus: number; memMb: number };
  joinedAt: string;
}

export const workerHome = () => process.env.PAASMCP_WORKER_HOME || WORKER_HOME;
export const workerRunDir = () => process.env.PAASMCP_WORKER_RUN_DIR || WORKER_RUN_DIR;
const configFile = () => path.join(workerHome(), "worker.json");

export function readWorkerConfig(): WorkerConfig {
  let raw: WorkerConfig;
  try {
    raw = JSON.parse(fs.readFileSync(configFile(), "utf-8"));
  } catch {
    throw new Error("This PC is not set up as a helper (run 'sudo paasmcp pool join <invite>').");
  }
  if (raw?.v !== 1 || typeof raw.name !== "string") throw new Error("Unknown helper configuration.");
  return raw;
}

function writeWorkerConfig(cfg: WorkerConfig): void {
  const tmp = `${configFile()}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, configFile());
}

function workerVersion(): string {
  // Installed copy (/usr/local/lib/paasmcp-worker/package.json) first, then the source tree's.
  for (const rel of ["./package.json", "../package.json"]) {
    try {
      const v = JSON.parse(fs.readFileSync(new URL(rel, import.meta.url), "utf-8")).version;
      if (v) return String(v).slice(0, 40);
    } catch {
      // try the next
    }
  }
  return "";
}

function docker(args: string[], opts: { input?: string; timeout?: number } = {}): string {
  return execFileSync("docker", args, {
    encoding: "utf-8",
    input: opts.input,
    stdio: ["pipe", "pipe", "pipe"],
    timeout: opts.timeout ?? 120_000,
    maxBuffer: 16 * 1024 * 1024,
  }).trim();
}

function dockerOk(args: string[]): boolean {
  return spawnSync("docker", args, { stdio: "ignore", timeout: 60_000 }).status === 0;
}

function firstLine(err: unknown): string {
  const e = err as { stderr?: string | Buffer; message?: string };
  const msg = String(e?.stderr || e?.message || err).trim().split("\n").filter(Boolean).pop() || "unknown error";
  return msg.slice(0, 400);
}

/** The secrets folder must be a private directory of this user on a tmpfs, or nothing is written. */
export function checkSecretsDir(dir = workerRunDir()): void {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(dir);
  } catch {
    throw new Error(`The in-memory folder ${dir} is missing (it is recreated at boot by systemd-tmpfiles). Run 'sudo systemd-tmpfiles --create' or 'sudo paasmcp pool join' again.`);
  }
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error(`${dir} is not a plain folder.`);
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) throw new Error(`${dir} does not belong to this user.`);
  if ((st.mode & 0o077) !== 0) throw new Error(`${dir} is readable by other users (it must be mode 700).`);
  if (fs.statfsSync(dir).type !== TMPFS_MAGIC && process.env.PAASMCP_WORKER_ALLOW_DISK !== "1") {
    throw new Error(`${dir} is not in memory (tmpfs): refusing to write an app's variables to disk.`);
  }
}

function secretsInMemory(): boolean {
  try {
    checkSecretsDir();
    return true;
  } catch {
    return false;
  }
}

function envFileOf(copyId: string): string {
  return path.join(workerRunDir(), `${copyId}.env`);
}

export function facts(cfg: WorkerConfig): WorkerFacts {
  let arch = os.arch();
  let dockerVersion = "";
  let diskFreeGb = 0;
  try {
    const info = docker(["info", "--format", "{{.Architecture}} {{.ServerVersion}} {{.DockerRootDir}}"], { timeout: 15_000 }).split(" ");
    arch = info[0] || arch;
    dockerVersion = info[1] || "";
    for (const dir of [info[2], "/var/lib", "/"]) {
      try {
        const s = fs.statfsSync(dir);
        diskFreeGb = (s.bavail * s.bsize) / 1024 ** 3;
        break;
      } catch {
        // no access to the Docker folder itself: its parent is close enough
      }
    }
  } catch {
    // Docker down: reported as no version
  }
  return {
    name: cfg.name,
    arch: normalizeArch(arch),
    cpus: os.cpus().length,
    memMb: Math.round(os.totalmem() / 1024 / 1024),
    diskFreeGb: Math.round(diskFreeGb * 10) / 10,
    give: cfg.give,
    dockerVersion,
    workerVersion: workerVersion(),
    load1: Math.round(os.loadavg()[0] * 100) / 100,
    secretsInMemory: secretsInMemory(),
  };
}

export function listCopies(): WorkerCopy[] {
  const out = docker([
    "ps", "-a", "--filter", "label=paasmcp.pool",
    "--format", '{{.State}}\t{{.Status}}\t{{.Label "paasmcp.copy"}}\t{{.Label "paasmcp.app"}}\t{{.Label "paasmcp.fingerprint"}}',
  ]);
  return out
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [state, status, copyId, app, fingerprint] = line.split("\t");
      return { copyId, app, running: state === "running", status, fingerprint };
    });
}

/** Deletes variable files whose copy no longer exists (a crash, a reboot that kept /run, a manual docker rm). */
function cleanOrphanEnv(copies: WorkerCopy[]): void {
  const alive = new Set(copies.map((c) => `${c.copyId}.env`));
  try {
    for (const f of fs.readdirSync(workerRunDir())) if (f.endsWith(".env") && !alive.has(f)) fs.rmSync(path.join(workerRunDir(), f), { force: true });
  } catch {
    // folder missing: nothing to clean
  }
}

function localFingerprint(tag: string): string | undefined {
  try {
    return imageFingerprint(JSON.parse(docker(["image", "inspect", "--format", "{{json .}}", tag], { timeout: 30_000 })));
  } catch {
    return undefined;
  }
}

/** What the running copies already take, in CPUs and MB (the owner's share caps the total). */
function usedByCopies(exceptCopy?: string): { cpus: number; memMb: number } {
  const names = docker(["ps", "-q", "--filter", "label=paasmcp.pool"]).split("\n").filter(Boolean);
  let cpus = 0;
  let memMb = 0;
  for (const id of names) {
    const [nano, mem, copy] = docker(["inspect", "--format", '{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{index .Config.Labels "paasmcp.copy"}}', id]).split(" ");
    if (copy === exceptCopy) continue;
    cpus += Number(nano) / 1e9 || 0;
    memMb += Number(mem) / 1024 / 1024 || 0;
  }
  return { cpus, memMb };
}

function runCopy(cfg: WorkerConfig, spec: CopySpec, bindIp: string): { container: string; id: string } {
  if (spec.originNodeId !== cfg.originNodeId) throw new Error("This PC belongs to another server's pool.");
  checkSecretsDir();
  const fp = localFingerprint(spec.image);
  if (!fp) throw new Error(`Image ${spec.image} is not on this PC yet.`);
  if (fp !== spec.fingerprint) throw new Error(`Image ${spec.image} does not match the fingerprint the server sent.`);

  const want = { cpus: Number(spec.cpus), memMb: Number(spec.memory.slice(0, -1)) };
  const used = usedByCopies(spec.copyId);
  if (used.cpus + want.cpus > cfg.give.cpus + 0.001 || used.memMb + want.memMb > cfg.give.memMb + 1) {
    throw new Error(
      `The owner of this PC gave ${cfg.give.cpus} CPUs and ${cfg.give.memMb} MB; copies already take ${Math.round(used.cpus * 100) / 100} CPUs and ${Math.round(used.memMb)} MB, and this one needs ${want.cpus} CPUs and ${want.memMb} MB.`
    );
  }

  const conf = JSON.parse(docker(["image", "inspect", "--format", "{{json .Config}}", spec.image])) as { Entrypoint?: string[] | null; Cmd?: string[] | null };
  const entrypoint = Array.isArray(conf.Entrypoint) ? conf.Entrypoint.map(String) : [];
  const cmd = Array.isArray(conf.Cmd) ? conf.Cmd.map(String) : [];
  if (!entrypoint.length && !cmd.length) throw new Error("The image has no command to run.");

  const name = `${COPY_CONTAINER_PREFIX}${spec.copyId}`;
  const envFile = envFileOf(spec.copyId);
  spawnSync("docker", ["rm", "-f", name], { stdio: "ignore" });
  fs.rmSync(envFile, { force: true });
  // 644 inside a 700 folder: only this user (and root) reach it on the PC, and the app's own user can
  // read it inside the container whatever uid the image runs as.
  fs.writeFileSync(envFile, renderEnvFile(spec.env), { mode: 0o644, flag: "wx" });
  try {
    const id = docker(buildRunArgs(spec, bindIp, envFile, entrypoint, cmd));
    pruneOldImages(spec.app, spec.image);
    return { container: name, id: id.slice(0, 12) };
  } catch (err) {
    spawnSync("docker", ["rm", "-f", name], { stdio: "ignore" });
    fs.rmSync(envFile, { force: true });
    throw new Error(`docker run failed: ${firstLine(err)}`);
  }
}

/** Keeps only the newest image of each app (older ones still used by a running copy are kept by Docker). */
function pruneOldImages(app: string, keep: string): void {
  try {
    const tags = docker(["image", "ls", "--format", "{{.Repository}}:{{.Tag}}", `${POOL_IMAGE_REPO}/${app}`]).split("\n").filter(Boolean);
    for (const t of tags) if (t !== keep) spawnSync("docker", ["image", "rm", t], { stdio: "ignore" });
  } catch {
    // best effort
  }
}

function stopCopy(copyId: string): { stopped: boolean } {
  const name = `${COPY_CONTAINER_PREFIX}${copyId}`;
  const existed = dockerOk(["inspect", name]);
  if (existed) {
    spawnSync("docker", ["stop", "-t", "10", name], { stdio: "ignore", timeout: 60_000 });
    spawnSync("docker", ["rm", "-f", name], { stdio: "ignore" });
  }
  fs.rmSync(envFileOf(copyId), { force: true });
  return { stopped: existed };
}

function forget(): { stopped: number } {
  const copies = listCopies();
  for (const c of copies) stopCopy(c.copyId);
  try {
    for (const t of docker(["image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter", `reference=${POOL_IMAGE_REPO}/*`]).split("\n").filter(Boolean)) {
      spawnSync("docker", ["image", "rm", t], { stdio: "ignore" });
    }
  } catch {
    // best effort
  }
  cleanOrphanEnv([]);
  // Revoke the origin's key: from now on this PC takes no more orders.
  fs.rmSync(path.join(workerHome(), ".ssh", "authorized_keys"), { force: true });
  fs.rmSync(configFile(), { force: true });
  return { stopped: copies.length };
}

/** Tags `docker load` reports ("Loaded image: x:y") that are not under paasmcp-pool/. */
export function foreignLoadedTags(loadOutput: string): string[] {
  const out: string[] = [];
  for (const line of loadOutput.split("\n")) {
    const m = /^Loaded image:\s*(\S+)\s*$/.exec(line.trim());
    if (m && !m[1].startsWith(`${POOL_IMAGE_REPO}/`)) out.push(m[1]);
  }
  return out;
}

function loadImage(tag: string, fingerprint: string): Promise<{ loaded: boolean }> {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", ["load", "--quiet"], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout = (stdout + String(d)).slice(-20_000)));
    child.stderr.on("data", (d) => (stderr = (stderr + String(d)).slice(-2000)));
    process.stdin.pipe(child.stdin);
    child.on("error", (err) => reject(err));
    child.on("close", (code) => {
      if (code !== 0) return reject(new Error(`docker load failed: ${stderr.trim().split("\n").pop() || code}`));
      // An image archive can carry any tag. Anything outside paasmcp-pool/ is untagged at once, so the
      // origin can never replace one of the owner's own images on this PC (say, postgres:16).
      const foreign = foreignLoadedTags(stdout);
      for (const t of foreign) spawnSync("docker", ["image", "rm", "--force", "--no-prune", t], { stdio: "ignore" });
      if (foreign.length) {
        spawnSync("docker", ["image", "rm", tag], { stdio: "ignore" });
        return reject(new Error(`The image archive carried other tags (${foreign.slice(0, 3).join(", ")}); they were removed and nothing was loaded.`));
      }
      const fp = localFingerprint(tag);
      if (fp !== fingerprint) {
        spawnSync("docker", ["image", "rm", tag], { stdio: "ignore" });
        return reject(new Error(`The image received does not match the fingerprint ${fingerprint.slice(0, 12)} (got ${fp ? fp.slice(0, 12) : "no image"}). It was removed.`));
      }
      resolve({ loaded: true });
    });
  });
}

function readStdinJson(): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    process.stdin.on("data", (d: Buffer) => {
      size += d.length;
      if (size > MAX_JSON_INPUT) {
        reject(new Error("Input too large."));
        process.stdin.destroy();
        return;
      }
      chunks.push(d);
    });
    process.stdin.on("end", () => {
      try {
        const text = Buffer.concat(chunks).toString("utf-8").trim();
        resolve(text ? JSON.parse(text) : {});
      } catch {
        reject(new Error("Input is not JSON."));
      }
    });
    process.stdin.on("error", reject);
  });
}

function log(entry: Record<string, unknown>): void {
  try {
    const file = path.join(workerHome(), "worker.log");
    try {
      if (fs.statSync(file).size > LOG_MAX_BYTES) fs.renameSync(file, `${file}.1`);
    } catch {
      // first line
    }
    fs.appendFileSync(file, JSON.stringify({ at: new Date().toISOString(), ...entry }) + "\n", { mode: 0o600 });
  } catch {
    // logging never blocks an order
  }
}

/** The IP the origin reached this PC on (its Tailscale IP): copies are published there and nowhere else. */
function bindIpFromSsh(): string {
  const parts = String(process.env.SSH_CONNECTION || "").split(" ");
  return validateIpv4(parts[2], "helper IP (from SSH_CONNECTION)");
}

export async function handleOrder(raw: string | undefined): Promise<unknown> {
  const { op, args } = parseOrder(raw);
  const cfg = readWorkerConfig();
  switch (op) {
    case "hello": {
      const input = await readStdinJson();
      const nonce = String(input.nonce || "");
      if (!/^[0-9a-f]{32,64}$/.test(nonce)) throw new Error("Bad nonce.");
      if (!cfg.proofKey) throw new Error("This PC already answered its invite. To join again, run 'sudo paasmcp pool join' with a new invite.");
      if (String(input.inviteId || "") !== cfg.inviteId) throw new Error("This PC joined with a different invite.");
      const proof = helloProof(cfg.proofKey, cfg.inviteId, nonce, cfg.name);
      delete cfg.proofKey;
      writeWorkerConfig(cfg);
      return { name: cfg.name, proof, facts: facts(cfg) };
    }
    case "facts":
      return facts(cfg);
    case "list": {
      const copies = listCopies();
      cleanOrphanEnv(copies);
      return { facts: facts(cfg), copies };
    }
    case "has-image":
      return { present: localFingerprint(args[0]) === args[1] };
    case "load":
      return loadImage(args[0], args[1]);
    case "run": {
      const spec = validateCopySpec(await readStdinJson());
      return runCopy(cfg, spec, bindIpFromSsh());
    }
    case "stop":
      return stopCopy(args[0]);
    case "logs": {
      const res = spawnSync("docker", ["logs", "--tail", "40", `${COPY_CONTAINER_PREFIX}${args[0]}`], { encoding: "utf-8", timeout: 30_000 });
      return { logs: `${res.stdout || ""}${res.stderr || ""}`.slice(-6000) };
    }
    case "forget":
      return forget();
  }
}

/** Run once by `pool join` as this user: can it read its files, reach Docker and keep secrets in memory? */
export function selfTest(): { ok: boolean; problems: string[] } {
  const problems: string[] = [];
  try {
    readWorkerConfig();
  } catch (err) {
    problems.push(firstLine(err));
  }
  if (!dockerOk(["version"])) problems.push("The worker user cannot reach Docker (is it in the 'docker' group?).");
  try {
    checkSecretsDir();
  } catch (err) {
    problems.push(firstLine(err));
  }
  return { ok: problems.length === 0, problems };
}

async function main(): Promise<void> {
  if (process.argv[2] === "--selftest") {
    const r = selfTest();
    process.stdout.write(JSON.stringify(r) + "\n");
    process.exit(r.ok ? 0 : 1);
  }
  const raw = process.env.SSH_ORIGINAL_COMMAND;
  const started = Date.now();
  const op = String(raw || "").split(/\s+/)[0].slice(0, 20);
  try {
    const result = await handleOrder(raw);
    log({ op, args: String(raw || "").split(/\s+/).slice(1, 3), ok: true, ms: Date.now() - started });
    process.stdout.write(JSON.stringify({ ok: true, result }) + "\n");
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    log({ op, ok: false, error: error.slice(0, 300) });
    process.stdout.write(JSON.stringify({ ok: false, error }) + "\n");
    process.exitCode = 2;
  }
}

// Only when run as a program (sshd forced command), not when imported by tests.
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  main();
}
