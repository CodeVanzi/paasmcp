import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { ensureDirectories, PAAS_SSH_DIR } from "./config.js";
import { getSecrets } from "./vault.js";

export interface DeployKeyInfo {
  privateKeyPath: string;
  publicKeyPath: string;
  publicKey: string;
}

export function getOrCreateSshDeployKey(keyName = "paasmcp_deploy_ed25519"): DeployKeyInfo {
  ensureDirectories();
  const privateKeyPath = path.join(PAAS_SSH_DIR, keyName);
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
  return { privateKeyPath, publicKeyPath, publicKey };
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

export function cloneOrUpdateRepo(
  repoSource: string,
  targetDir: string,
  branch = "main"
): { commitHash: string; sourceType: "local" | "git" } {
  // Support local directory path directly as well as GitHub shorthand or URL
  if (fs.existsSync(repoSource) && fs.statSync(repoSource).isDirectory()) {
    fs.mkdirSync(targetDir, { recursive: true });
    execFileSync("cp", ["-a", `${repoSource}/.`, targetDir]);
    return { commitHash: "local-source", sourceType: "local" };
  }

  let gitUrl = repoSource;
  if (/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(repoSource)) {
    const sysSecrets = getSecrets("system");
    if (sysSecrets.GITHUB_TOKEN) {
      gitUrl = `https://x-access-token:${sysSecrets.GITHUB_TOKEN}@github.com/${repoSource}.git`;
    } else {
      gitUrl = `git@github.com:${repoSource}.git`;
    }
  }

  const keyInfo = getOrCreateSshDeployKey();
  const env = {
    ...process.env,
    GIT_SSH_COMMAND: `ssh -i ${keyInfo.privateKeyPath} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new`,
  };

  if (fs.existsSync(path.join(targetDir, ".git"))) {
    execFileSync("git", ["fetch", "--all"], { cwd: targetDir, env, stdio: "pipe" });
    execFileSync("git", ["checkout", branch], { cwd: targetDir, env, stdio: "pipe" });
    execFileSync("git", ["reset", "--hard", `origin/${branch}`], {
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
      execFileSync("git", ["clone", "--branch", branch, "--depth", "1", gitUrl, targetDir], {
        env,
        stdio: "pipe",
      });
    } catch {
      // Fallback if default branch is master or unspecified
      execFileSync("git", ["clone", "--depth", "1", gitUrl, targetDir], {
        env,
        stdio: "pipe",
      });
    }
  }

  let commitHash = "unknown";
  try {
    commitHash = execFileSync("git", ["rev-parse", "--short", "HEAD"], {
      cwd: targetDir,
      encoding: "utf-8",
    }).trim();
  } catch {
    // ignore
  }
  return { commitHash, sourceType: "git" };
}

export interface DetectedBuildPlan {
  runtimeType: string;
  dockerfilePath: string;
  detectedPort: number;
}

export function detectOrGenerateDockerfile(
  repoDir: string,
  overridePort?: number
): DetectedBuildPlan {
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

  const pkgJsonPath = path.join(repoDir, "package.json");
  if (fs.existsSync(pkgJsonPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    const scripts = pkg.scripts || {};
    const hasBuild = Boolean(scripts.build);
    const hasStart = Boolean(scripts.start);

    // Check if static Vite / SPA without server start script
    const isStaticSpa =
      (deps.vite || deps["react-scripts"] || deps.astro) && hasBuild && !hasStart && !deps.next;

    if (isStaticSpa) {
      const port = overridePort || 80;
      const df = `FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
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
    const startCmd = hasStart
      ? '["npm", "start"]'
      : pkg.main
        ? `["node", "${pkg.main}"]`
        : '["node", "index.js"]';

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

  const reqTxt = path.join(repoDir, "requirements.txt");
  const pyproject = path.join(repoDir, "pyproject.toml");
  if (fs.existsSync(reqTxt) || fs.existsSync(pyproject)) {
    const port = overridePort || 8000;
    let cmd = `["python", "main.py"]`;
    const reqContent = fs.existsSync(reqTxt) ? fs.readFileSync(reqTxt, "utf-8") : "";
    if (reqContent.includes("uvicorn") || reqContent.includes("fastapi")) {
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
ENV PORT=${port}
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

  if (fs.existsSync(path.join(repoDir, "go.mod"))) {
    const port = overridePort || 8080;
    const df = `FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

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

  if (fs.existsSync(path.join(repoDir, "index.html"))) {
    const port = overridePort || 80;
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
    "Could not auto-detect stack in repository (no Dockerfile, package.json, requirements.txt, pyproject.toml, go.mod, or index.html found)."
  );
}
