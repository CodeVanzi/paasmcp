import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { loadState, sanitizeSlug, saveState, validateBranchName } from "./config.js";
import { deployApp } from "./deployer.js";
import { gitEnv, resolveGitUrl } from "./github.js";
import { audit } from "./guard.js";

// Polling mode: a systemd timer runs `paasmcp poll` every few minutes and exits, so nothing stays in
// memory between checks and no public webhook URL is needed (works behind Tailscale only).

export function setPolling(appName: string, on: boolean): { app: string; autoDeploy: "poll" | undefined } {
  const slug = sanitizeSlug(appName);
  const state = loadState();
  const app = state.apps[slug];
  if (!app) throw new Error(`App '${slug}' not found.`);
  if (on && (!app.repoUrl || fs.existsSync(app.repoUrl))) throw new Error(`App '${slug}' was not deployed from a git repository; nothing to poll.`);
  app.autoDeploy = on ? "poll" : undefined;
  saveState(state);
  return { app: slug, autoDeploy: app.autoDeploy };
}

export function remoteHead(repoUrl: string, branch: string): string {
  const out = execFileSync("git", ["ls-remote", "--", resolveGitUrl(repoUrl), `refs/heads/${validateBranchName(branch)}`], {
    env: gitEnv(),
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 30_000,
  });
  const sha = out.split(/\s/)[0];
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error(`Branch '${branch}' not found in ${repoUrl}.`);
  return sha;
}

export async function pollRepos(head = remoteHead): Promise<{ checked: string[]; deployed: { app: string; commit: string }[]; errors: { app: string; error: string }[] }> {
  const checked: string[] = [];
  const deployed: { app: string; commit: string }[] = [];
  const errors: { app: string; error: string }[] = [];
  const state = loadState();
  for (const app of Object.values(state.apps).filter((a) => a.autoDeploy === "poll" && a.repoUrl && !a.trashedAt)) {
    checked.push(app.name);
    try {
      const sha = head(app.repoUrl!, app.branch);
      if (app.lastCommit && sha.startsWith(app.lastCommit)) continue;
      const result = await deployApp({ appName: app.name, repoSource: app.repoUrl!, branch: app.branch, trusted: app.trusted, trigger: "poll", announcedCommit: sha });
      deployed.push({ app: app.name, commit: result.commitHash });
      audit({ event: "poll.deploy", app: app.name, commit: result.commitHash });
    } catch (err) {
      errors.push({ app: app.name, error: err instanceof Error ? err.message.split("\n")[0] : String(err) });
    }
  }
  return { checked, deployed, errors };
}

export function installPollTimer(minutes = 2): { service: string; timer: string } {
  const service = "/etc/systemd/system/paasmcp-poll.service";
  const timer = "/etc/systemd/system/paasmcp-poll.timer";
  fs.writeFileSync(
    service,
    `[Unit]\nDescription=PaaSMCP git polling (auto-deploy without a public webhook)\n\n[Service]\nType=oneshot\nEnvironment=PAASMCP_ROOT=${process.env.PAASMCP_ROOT || "/opt/homelab"}\nExecStart=${process.execPath} ${path.resolve(process.argv[1])} poll\n`
  );
  fs.writeFileSync(
    timer,
    `[Unit]\nDescription=Run PaaSMCP git polling every ${minutes} min\n\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=${minutes}min\n\n[Install]\nWantedBy=timers.target\n`
  );
  execFileSync("systemctl", ["daemon-reload"]);
  execFileSync("systemctl", ["enable", "--now", "paasmcp-poll.timer"]);
  return { service, timer };
}
