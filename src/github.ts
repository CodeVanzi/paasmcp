import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { ensureDirectories, PAAS_SSH_DIR, validateBranchName } from "./config.js";
import { getSecrets } from "./vault.js";

export interface DeployKeyInfo {
  privateKeyPath: string;
  publicKeyPath: string;
  publicKey: string;
  fingerprint: string;
}

export function getOrCreateSshDeployKey(keyName = "paasmcp_deploy_ed25519"): DeployKeyInfo {
  const safeKeyName = keyName.replace(/[^a-zA-Z0-9_.-]/g, "");
  ensureDirectories();
  const privateKeyPath = path.join(PAAS_SSH_DIR, safeKeyName);
  const publicKeyPath = `${privateKeyPath}.pub`;

  if (!fs.existsSync(privateKeyPath)) {
    execFileSync(
      "ssh-keygen",
      [
        "-t",
        "ed25519",
        "-C",
        "paasmcp@server",
        "-f",
        privateKeyPath,
        "-N",
        "",
      ],
      { stdio: "pipe" }
    );
    fs.chmodSync(privateKeyPath, 0o600);
  }

  const publicKey = fs.readFileSync(publicKeyPath, "utf-8").trim();
  const keyParts = publicKey.split(" ");
  const rawKeyBody = keyParts[1] || publicKey;
  const fingerprint =
    "SHA256:" +
    crypto
      .createHash("sha256")
      .update(Buffer.from(rawKeyBody, "base64"))
      .digest("base64")
      .replace(/=+$/, "");

  return { privateKeyPath, publicKeyPath, publicKey, fingerprint };
}

export async function registerGitHubDeployKey(
  repoFullName: string,
  title = "paasmcp-deploy-key"
): Promise<{ registered: boolean; message: string; publicKey: string }> {
  const keyInfo = getOrCreateSshDeployKey();
  const sysSecrets = getSecrets("system");
  const githubToken = sysSecrets.GITHUB_TOKEN || process.env.GITHUB_TOKEN;

  if (!githubToken) {
    return {
      registered: false,
      message:
        "No GITHUB_TOKEN found in 'system' vault. Add the public key manually to GitHub -> Settings -> Deploy Keys, or store GITHUB_TOKEN in the 'system' vault.",
      publicKey: keyInfo.publicKey,
    };
  }

  const cleanRepo = repoFullName
    .replace(/^https?:\/\/github\.com\//, "")
    .replace(/^git@github\.com:/, "")
    .replace(/\.git$/, "");

  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(cleanRepo)) {
    throw new Error(`Invalid GitHub repository format: "${repoFullName}". Expected "owner/repo".`);
  }

  const res = await fetch(`https://api.github.com/repos/${cleanRepo}/keys`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${githubToken}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "paasmcp-agent",
    },
    body: JSON.stringify({
      title,
      key: keyInfo.publicKey,
      read_only: true,
    }),
  });

  if (res.ok) {
    return {
      registered: true,
      message: `Deploy key successfully registered on GitHub repository ${cleanRepo}.`,
      publicKey: keyInfo.publicKey,
    };
  }

  const bodyText = await res.text();
  if (res.status === 422 && bodyText.includes("key is already in use")) {
    return {
      registered: true,
      message: `Deploy key is already registered on GitHub repository ${cleanRepo}.`,
      publicKey: keyInfo.publicKey,
    };
  }

  return {
    registered: false,
    message: `GitHub API returned ${res.status}: ${bodyText}`,
    publicKey: keyInfo.publicKey,
  };
}

export function resolveGitUrl(repoSource: string): string {
  let gitUrl = repoSource.trim();
  if (gitUrl.startsWith("-")) {
    throw new Error("Invalid repository source URL.");
  }
  if (/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(gitUrl)) {
    const sysSecrets = getSecrets("system");
    if (sysSecrets.GITHUB_TOKEN) {
      // The token never goes into the URL: it would be saved in the clone's .git/config (and copied
      // into the app's image by a "COPY . ." Dockerfile). gitEnv() sends it as a header instead.
      gitUrl = `https://github.com/${gitUrl}.git`;
    } else {
      gitUrl = `git@github.com:${gitUrl}.git`;
    }
  }
  return gitUrl;
}

export function gitEnv(): NodeJS.ProcessEnv {
  const keyInfo = getOrCreateSshDeployKey();
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    GIT_SSH_COMMAND: `ssh -i ${keyInfo.privateKeyPath} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new`,
  };
  // A saved GitHub token reaches only github.com over HTTPS, as a header passed through the
  // environment (not the command line, not the clone's config).
  const token = getSecrets("system").GITHUB_TOKEN;
  if (token) {
    // Added after any GIT_CONFIG_* entries already in the environment (a proxy, for example).
    const n = Math.max(0, Number.parseInt(String(env.GIT_CONFIG_COUNT || "0"), 10) || 0);
    env.GIT_CONFIG_COUNT = String(n + 1);
    env[`GIT_CONFIG_KEY_${n}`] = "http.https://github.com/.extraheader";
    env[`GIT_CONFIG_VALUE_${n}`] = `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString("base64")}`;
  }
  return env;
}

export function cloneOrUpdateRepo(
  repoSource: string,
  targetDir: string,
  branch = "main",
  /** Exact commit to check out (active-active peers run the origin's version, not the branch head). */
  commit?: string
): { commitHash: string; commitSha?: string; sourceType: "local" | "git" } {
  const safeBranch = validateBranchName(branch);
  if (commit !== undefined && !/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error(`Invalid commit '${commit}': a full 40-character SHA is expected.`);
  }

  // Support local directory path directly as well as GitHub shorthand or URL
  if (fs.existsSync(repoSource) && fs.statSync(repoSource).isDirectory()) {
    fs.mkdirSync(targetDir, { recursive: true });
    execFileSync("cp", ["-a", `${repoSource}/.`, targetDir]);
    return { commitHash: "local-source", sourceType: "local" };
  }

  const gitUrl = resolveGitUrl(repoSource);
  const env = gitEnv();

  if (fs.existsSync(path.join(targetDir, ".git"))) {
    // Also cleans clones made before the token moved out of the URL.
    execFileSync("git", ["remote", "set-url", "origin", gitUrl], { cwd: targetDir, env, stdio: "pipe" });
    execFileSync("git", ["fetch", "--all"], { cwd: targetDir, env, stdio: "pipe" });
    execFileSync("git", ["checkout", safeBranch], { cwd: targetDir, env, stdio: "pipe" });
    execFileSync("git", ["reset", "--hard", `origin/${safeBranch}`], {
      cwd: targetDir,
      env,
      stdio: "pipe",
    });
  } else {
    if (fs.existsSync(targetDir)) {
      fs.rmSync(targetDir, { recursive: true, force: true });
    }
    fs.mkdirSync(path.dirname(targetDir), { recursive: true });
    try {
      execFileSync(
        "git",
        ["clone", "--branch", safeBranch, "--depth", "1", "--", gitUrl, targetDir],
        {
          env,
          stdio: "pipe",
        }
      );
    } catch {
      // Fallback if default branch is master or unspecified
      execFileSync("git", ["clone", "--depth", "1", "--", gitUrl, targetDir], {
        env,
        stdio: "pipe",
      });
    }
  }

  if (commit) {
    // Shallow clones may not hold it yet; GitHub serves any reachable commit by id.
    try {
      execFileSync("git", ["fetch", "--depth", "1", "origin", commit], { cwd: targetDir, env, stdio: "pipe" });
    } catch {
      execFileSync("git", ["fetch", "origin"], { cwd: targetDir, env, stdio: "pipe" });
    }
    execFileSync("git", ["checkout", "--detach", commit], { cwd: targetDir, env, stdio: "pipe" });
  }

  let commitHash = "unknown";
  let commitSha: string | undefined;
  try {
    commitSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: targetDir, encoding: "utf-8" }).trim();
    commitHash = execFileSync("git", ["rev-parse", "--short", "HEAD"], {
      cwd: targetDir,
      encoding: "utf-8",
    }).trim();
  } catch {
    // ignore
  }
  return { commitHash, commitSha, sourceType: "git" };
}

/** Subject, author and commit date of HEAD in a checked-out repository (empty when unknown). */
export function headCommitInfo(repoDir: string): { subject?: string; author?: string; date?: string } {
  try {
    const out = execFileSync("git", ["log", "-1", "--format=%s%x00%an%x00%cI"], {
      cwd: repoDir,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    const [subject, author, date] = out.replace(/\n$/, "").split("\0");
    return { subject, author, date: date && !Number.isNaN(Date.parse(date)) ? new Date(date).toISOString() : undefined };
  } catch {
    return {};
  }
}

export interface DetectedBuildPlan {
  runtimeType: string;
  dockerfilePath: string;
  detectedPort: number;
  composeFile?: string;
  primaryServiceName?: string;
  serviceNames?: string[];
}

const SAFE_NAME = /^[a-zA-Z0-9_.-]+$/;

/** Finds the ASP.NET project to publish: root *.csproj first, else one web project one folder down. */
function findDotnetProject(repoDir: string): { csproj: string; assembly: string; version: string } | undefined {
  const csprojIn = (dir: string) =>
    fs.readdirSync(path.join(repoDir, dir)).filter((f) => f.endsWith(".csproj") && SAFE_NAME.test(f)).sort();
  const candidates = csprojIn(".");
  if (candidates.length === 0) {
    for (const top of ["src", "."]) {
      if (!fs.existsSync(path.join(repoDir, top))) continue;
      for (const d of fs.readdirSync(path.join(repoDir, top)).sort()) {
        if (!SAFE_NAME.test(d) || d.startsWith(".")) continue;
        const rel = top === "." ? d : `${top}/${d}`;
        if (!fs.statSync(path.join(repoDir, rel)).isDirectory()) continue;
        candidates.push(...csprojIn(rel).map((f) => `${rel}/${f}`));
      }
      if (candidates.length > 0) break;
    }
  }
  if (candidates.length === 0) return undefined;
  const read = (c: string) => fs.readFileSync(path.join(repoDir, c), "utf-8");
  const web = candidates.filter((c) => /Sdk="Microsoft\.NET\.Sdk\.Web"/.test(read(c)));
  if (web.length > 1) throw new Error(`Several ASP.NET projects found (${web.join(", ")}); add a Dockerfile to pick one.`);
  const csproj = web[0] || (candidates.length === 1 ? candidates[0] : undefined);
  if (!csproj) throw new Error(`Several .csproj files found (${candidates.join(", ")}); add a Dockerfile to pick one.`);
  const xml = read(csproj);
  const asm = xml.match(/<AssemblyName>\s*([^<]+?)\s*<\/AssemblyName>/)?.[1];
  const assembly = asm && SAFE_NAME.test(asm) ? asm : path.basename(csproj, ".csproj");
  const tfm = xml.match(/<TargetFrameworks?>\s*net(\d+\.\d+)/)?.[1];
  return { csproj, assembly, version: tfm && Number(tfm) >= 6 ? tfm : "8.0" };
}

export function detectOrGenerateDockerfile(
  repoDir: string,
  overridePort?: number
): DetectedBuildPlan {
  // 1. Check for Multi-Service Docker Compose pass-through first
  const composeCandidates = ["docker-compose.yml", "docker-compose.yaml", "compose.yaml", "compose.yml"];
  for (const candidate of composeCandidates) {
    const composePath = path.join(repoDir, candidate);
    if (fs.existsSync(composePath)) {
      const raw = fs.readFileSync(composePath, "utf-8");
      const parsed = YAML.parse(raw) as {
        services?: Record<
          string,
          {
            ports?: Array<string | number>;
            expose?: Array<string | number>;
            privileged?: boolean;
            network_mode?: string;
            volumes?: string[];
          }
        >;
      };
      if (parsed && parsed.services && Object.keys(parsed.services).length > 0) {
        const serviceNames = Object.keys(parsed.services);
        const preferredNames = ["web", "app", "api", "frontend", "server"];
        const primaryServiceName =
          preferredNames.find((n) => serviceNames.includes(n)) || serviceNames[0];

        let detectedPort = overridePort || 3000;
        const primarySvc = parsed.services[primaryServiceName];
        if (!overridePort && primarySvc?.ports && primarySvc.ports.length > 0) {
          const firstPort = String(primarySvc.ports[0]);
          const parts = firstPort.split(":");
          const containerPortPart = parts[parts.length - 1].replace(/\/.*$/, "");
          if (/^\d+$/.test(containerPortPart)) {
            detectedPort = Number(containerPortPart);
          }
        }
        return {
          runtimeType: `multi-service-compose (${serviceNames.length} services)`,
          dockerfilePath: candidate,
          detectedPort,
          composeFile: candidate,
          primaryServiceName,
          serviceNames,
        };
      }
    }
  }

  // 2. Custom Dockerfile
  const existingDockerfile = path.join(repoDir, "Dockerfile");
  if (fs.existsSync(existingDockerfile)) {
    const content = fs.readFileSync(existingDockerfile, "utf-8");
    const exposeMatch = content.match(/^EXPOSE\s+(\d+)/m);
    const detectedPort = overridePort || (exposeMatch ? Number(exposeMatch[1]) : 3000);
    return {
      runtimeType: "custom-dockerfile",
      dockerfilePath: "Dockerfile",
      detectedPort,
    };
  }

  // 3. Node.js / Next.js / Static SPA
  const pkgJsonPath = path.join(repoDir, "package.json");
  if (fs.existsSync(pkgJsonPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    const scripts = pkg.scripts || {};
    const hasBuild = Boolean(scripts.build);
    const hasStart = Boolean(scripts.start);

    const isStaticSpa =
      (deps.vite || deps["react-scripts"] || deps.astro) && hasBuild && !hasStart && !deps.next;

    if (isStaticSpa) {
      const port = 80; // nginx listens on 80 whatever the override
      const outDir = deps["react-scripts"] ? "build" : "dist";
      const df = `FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/${outDir} /usr/share/nginx/html
EXPOSE ${port}
CMD ["nginx", "-g", "daemon off;"]
`;
      fs.writeFileSync(path.join(repoDir, "Dockerfile.paasmcp"), df);
      return {
        runtimeType: "nodejs-static-spa",
        dockerfilePath: "Dockerfile.paasmcp",
        detectedPort: port,
      };
    }

    const port = overridePort || 3000;
    const buildStep = hasBuild ? "RUN npm run build" : "";
    const safeMain =
      pkg.main && /^[a-zA-Z0-9_./-]+$/.test(String(pkg.main))
        ? String(pkg.main)
        : "index.js";
    const startCmd = hasStart
      ? '["npm", "start"]'
      : `["node", "${safeMain}"]`;

    const df = `FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
${buildStep}
ENV NODE_ENV=production
ENV PORT=${port}
EXPOSE ${port}
CMD ${startCmd}
`;
    fs.writeFileSync(path.join(repoDir, "Dockerfile.paasmcp"), df);
    return {
      runtimeType: deps.next ? "nextjs" : "nodejs",
      dockerfilePath: "Dockerfile.paasmcp",
      detectedPort: port,
    };
  }

  // 4. Python (FastAPI / Flask / Django / Script)
  const reqTxt = path.join(repoDir, "requirements.txt");
  const pyproject = path.join(repoDir, "pyproject.toml");
  if (fs.existsSync(reqTxt) || fs.existsSync(pyproject)) {
    const port = overridePort || 8000;
    let cmd = `["python", "main.py"]`;
    let extraInstall = "";
    const reqContent = fs.existsSync(reqTxt) ? fs.readFileSync(reqTxt, "utf-8") : "";
    // Django first: many Django projects also list uvicorn (ASGI), and manage.py is the stronger signal.
    if (fs.existsSync(path.join(repoDir, "manage.py"))) {
      // Django: serve the project's WSGI app with gunicorn (never the dev server).
      const wsgiDir = fs.readdirSync(repoDir).find((d) => /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(d) && fs.existsSync(path.join(repoDir, d, "wsgi.py")));
      if (!wsgiDir) throw new Error("Django project found (manage.py) but no <project>/wsgi.py; add a Dockerfile.");
      cmd = `["gunicorn", "-b", "0.0.0.0:${port}", "${wsgiDir}.wsgi"]`;
      if (!/gunicorn/i.test(reqContent)) extraInstall = "RUN pip install --no-cache-dir gunicorn\n";
    } else if (reqContent.includes("uvicorn") || reqContent.includes("fastapi")) {
      const entry = fs.existsSync(path.join(repoDir, "app.py")) ? "app:app" : "main:app";
      cmd = `["uvicorn", "${entry}", "--host", "0.0.0.0", "--port", "${port}"]`;
    } else if (reqContent.includes("gunicorn")) {
      const entry = fs.existsSync(path.join(repoDir, "app.py")) ? "app:app" : "main:app";
      cmd = `["gunicorn", "-b", "0.0.0.0:${port}", "${entry}"]`;
    }
    const df = `FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; elif [ -f pyproject.toml ]; then pip install --no-cache-dir .; fi
${extraInstall}ENV PORT=${port}
EXPOSE ${port}
CMD ${cmd}
`;
    fs.writeFileSync(path.join(repoDir, "Dockerfile.paasmcp"), df);
    return {
      runtimeType: "python",
      dockerfilePath: "Dockerfile.paasmcp",
      detectedPort: port,
    };
  }

  // 5. Go
  if (fs.existsSync(path.join(repoDir, "go.mod"))) {
    const port = overridePort || 8080;
    // Many Go repos keep main in cmd/<name>/; build that when the root has no Go files.
    const rootHasGo = fs.readdirSync(repoDir).some((f) => f.endsWith(".go"));
    const cmdDir = path.join(repoDir, "cmd");
    const sub = !rootHasGo && fs.existsSync(cmdDir) ? fs.readdirSync(cmdDir).filter((d) => /^[a-zA-Z0-9_-]+$/.test(d)).sort()[0] : undefined;
    const pkgPath = sub ? `./cmd/${sub}` : ".";
    const df = `FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server ${pkgPath}

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/server /app/server
ENV PORT=${port}
EXPOSE ${port}
CMD ["/app/server"]
`;
    fs.writeFileSync(path.join(repoDir, "Dockerfile.paasmcp"), df);
    return {
      runtimeType: "go",
      dockerfilePath: "Dockerfile.paasmcp",
      detectedPort: port,
    };
  }

  // 5b. C# / .NET (ASP.NET Core): a *.csproj at the root, or a single web project one folder down (e.g. src/Api/).
  const dotnet = findDotnetProject(repoDir);
  if (dotnet) {
    const port = overridePort || 8080;
    const df = `FROM mcr.microsoft.com/dotnet/sdk:${dotnet.version} AS build
WORKDIR /src
COPY . .
RUN dotnet publish "${dotnet.csproj}" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:${dotnet.version}
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://+:${port}
ENV PORT=${port}
EXPOSE ${port}
ENTRYPOINT ["dotnet", "${dotnet.assembly}.dll"]
`;
    fs.writeFileSync(path.join(repoDir, "Dockerfile.paasmcp"), df);
    return {
      runtimeType: "dotnet",
      dockerfilePath: "Dockerfile.paasmcp",
      detectedPort: port,
    };
  }

  // 6. Static HTML
  if (fs.existsSync(path.join(repoDir, "index.html"))) {
    const port = 80; // nginx listens on 80 whatever the override
    const df = `FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE ${port}
CMD ["nginx", "-g", "daemon off;"]
`;
    fs.writeFileSync(path.join(repoDir, "Dockerfile.paasmcp"), df);
    return {
      runtimeType: "static-html",
      dockerfilePath: "Dockerfile.paasmcp",
      detectedPort: port,
    };
  }

  throw new Error(
    "Could not auto-detect stack in repository (no docker-compose.yml, Dockerfile, package.json, requirements.txt, pyproject.toml, go.mod, *.csproj, or index.html found)."
  );
}
