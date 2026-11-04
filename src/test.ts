import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import YAML from "yaml";

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "paasmcp-test-"));
process.env.PAASMCP_ROOT = tempRoot;
process.env.PAASMCP_OFFLINE_TEST = "1";

test("PaaSMCP Full Security & Feature Suite", async (t) => {
  const config = await import("./config.js");
  const vault = await import("./vault.js");
  const github = await import("./github.js");
  const deployer = await import("./deployer.js");
  const database = await import("./database.js");
  const federation = await import("./federation.js");

  await t.test("1. Sanitizes slugs, allocates ports, and blocks injection inputs", () => {
    assert.equal(config.sanitizeSlug("Meu App_Teste 01!"), "meu-app-teste-01");
    const state = config.loadState();
    const port1 = config.allocateAppPort(state);
    assert.equal(port1, 4000);

    // Reject malicious env keys or branch names
    assert.throws(() => config.validateEnvKey("BAD-KEY;rm -rf /"));
    assert.throws(() => config.validateBranchName("--upload-pack=evil"));
    assert.throws(() => config.validateBranchName("main..evil"));
    assert.equal(config.validateResourceLimit("512m", "memory"), "512m");
    assert.throws(() => config.validateResourceLimit("512m;evil", "memory"));
  });

  await t.test("2. Encrypts, masks, and decrypts Vault secrets & binary payloads (AES-256-GCM)", () => {
    vault.setSecretEntries("demo-app", {
      API_SECRET: "sk_live_9876543210abcdef",
      SHORT: "1234",
    });

    const masked = vault.listMaskedSecrets("demo-app");
    assert.equal(masked.API_SECRET, "sk_l****def");
    assert.equal(masked.SHORT, "********");

    const decrypted = vault.getSecrets("demo-app");
    assert.equal(decrypted.API_SECRET, "sk_live_9876543210abcdef");
    assert.equal(decrypted.SHORT, "1234");

    // Binary AES-256-GCM roundtrip + tamper detection
    const sampleBuf = Buffer.from("PostgreSQL binary dump payload", "utf-8");
    const encBuf = vault.encryptBinaryPayload(sampleBuf);
    const decBuf = vault.decryptBinaryPayload(encBuf);
    assert.deepEqual(decBuf, sampleBuf);

    // Flip 1 bit in ciphertext and verify GCM auth tag rejects tampering
    const tampered = Buffer.from(encBuf);
    tampered[tampered.length - 1] ^= 0xff;
    assert.throws(() => vault.decryptBinaryPayload(tampered));
  });

  await t.test("3. Auto-generates Dockerfile and sanitizes Multi-Service docker-compose.yml", () => {
    const nodeAppDir = path.join(tempRoot, "sample-node");
    fs.mkdirSync(nodeAppDir, { recursive: true });
    fs.writeFileSync(
      path.join(nodeAppDir, "package.json"),
      JSON.stringify({
        name: "sample-node",
        scripts: { start: "node server.js" },
      })
    );

    const plan = github.detectOrGenerateDockerfile(nodeAppDir);
    assert.equal(plan.runtimeType, "nodejs");
    assert.equal(plan.detectedPort, 3000);
    assert.ok(fs.existsSync(path.join(nodeAppDir, plan.dockerfilePath)));

    // Multi-service docker-compose pass-through with untrusted fields
    const composeAppDir = path.join(tempRoot, "sample-compose");
    fs.mkdirSync(composeAppDir, { recursive: true });
    const untrustedCompose = `services:
  web:
    build: .
    privileged: true
    network_mode: host
    ports:
      - "0.0.0.0:8080:8080"
    volumes:
      - /etc/shadow:/mnt/shadow
      - appdata:/data
  worker:
    build: ./worker
    ports:
      - "9000:9000"
volumes:
  appdata: {}
`;
    const composePath = path.join(composeAppDir, "docker-compose.yml");
    fs.writeFileSync(composePath, untrustedCompose);

    const composePlan = github.detectOrGenerateDockerfile(composeAppDir);
    assert.equal(composePlan.composeFile, "docker-compose.yml");
    assert.equal(composePlan.primaryServiceName, "web");
    assert.equal(composePlan.detectedPort, 8080);

    const { yaml: sanitizedYaml, findings } = deployer.generateSanitizedComposeFromRepo({
      repoComposePath: composePath,
      slug: "my-stack",
      containerName: "paasmcp-my-stack",
      localPort: 4005,
      internalPort: 8080,
      primaryServiceName: "web",
      memoryLimit: "512m",
      cpuLimit: "1.0",
    });

    const parsed = YAML.parse(sanitizedYaml);
    // Verify privileged, network_mode, and host bind mount (/etc/shadow) were stripped
    assert.equal(parsed.services.web.privileged, undefined);
    assert.equal(parsed.services.web.network_mode, undefined);
    assert.deepEqual(parsed.services.web.volumes, ["appdata:/data"]);
    // Verify loopback-only binding on web and no host port on worker
    assert.deepEqual(parsed.services.web.ports, ["127.0.0.1:4005:8080"]);
    assert.equal(parsed.services.worker.ports, undefined);
    assert.deepEqual(parsed.services.web.env_file, [".env.runtime"]);
    assert.deepEqual(parsed.services.worker.env_file, [".env.runtime"]);
    assert.ok(findings.includes("web.privileged"));
    assert.ok(findings.includes("web.volumes: /etc/shadow"));
  });

  await t.test("3b. Blocks disguised host access in compose; keeps it only for trusted apps", () => {
    const dir = path.join(tempRoot, "sneaky-compose");
    fs.mkdirSync(dir, { recursive: true });
    const composePath = path.join(dir, "docker-compose.yml");
    fs.writeFileSync(
      composePath,
      `services:
  web:
    build:
      context: .
      additional_contexts:
        host: /
    uts: host
    volumes_from:
      - paasmcp-dashboard
    extends:
      file: /etc/other.yml
      service: x
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
      - ~/.ssh:/root/.ssh
      - \${HOME}:/home
      - ./data:/data
      - cache:/cache
volumes:
  cache: {}
  sneaky:
    driver: local
    driver_opts: { type: none, o: bind, device: /etc }
`
    );
    const base = {
      repoComposePath: composePath,
      slug: "sneaky",
      containerName: "paasmcp-sneaky",
      localPort: 4010,
      internalPort: 80,
      primaryServiceName: "web",
    };

    const untrusted = deployer.generateSanitizedComposeFromRepo(base);
    const web = YAML.parse(untrusted.yaml).services.web;
    assert.deepEqual(web.volumes, ["./data:/data", "cache:/cache"]);
    assert.equal(web.uts, undefined);
    assert.equal(web.volumes_from, undefined);
    assert.equal(web.extends, undefined);
    assert.equal(web.build.additional_contexts, undefined);
    assert.deepEqual(YAML.parse(untrusted.yaml).volumes.sneaky, {});

    const trusted = deployer.generateSanitizedComposeFromRepo({ ...base, trusted: true });
    const tweb = YAML.parse(trusted.yaml).services.web;
    assert.equal(tweb.volumes.length, 5);
    assert.equal(tweb.uts, "host");
    // Never relaxed, even for trusted apps: extends, extra build contexts, loopback-only ports.
    assert.equal(tweb.extends, undefined);
    assert.equal(tweb.build.additional_contexts, undefined);
    assert.deepEqual(tweb.ports, ["127.0.0.1:4010:80"]);
  });

  await t.test("4. Creates & restores AES-256-GCM encrypted database backups with SHA-256 check", () => {
    const state = config.loadState();
    state.databases["demo-app-postgres"] = {
      name: "demo-app-postgres",
      engine: "postgres",
      mode: "shared",
      appName: "demo-app",
      dbName: "db_demo_app",
      dbUser: "user_demo_app",
      host: "paasmcp-postgres",
      port: 5432,
      localPort: 5432,
      createdAt: new Date().toISOString(),
    };
    config.saveState(state);

    const backupRec = database.backupDatabase("demo-app", "postgres");
    assert.equal(backupRec.encrypted, true);
    assert.ok(fs.existsSync(backupRec.filePath));

    const restoreRes = database.restoreDatabase(backupRec.id);
    assert.equal(restoreRes.restored, true);
    assert.ok(restoreRes.restoredBytes > 10);
  });

  await t.test("5. Verifies GitHub Webhook HMAC-SHA256 signatures and triggers matched branch rebuilds", async () => {
    const secret = federation.getOrCreateWebhookSecret();
    const body = JSON.stringify({
      ref: "refs/heads/main",
      repository: { full_name: "acme/demo-saas" },
    });
    const validSig =
      "sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex");

    assert.equal(federation.verifyGitHubWebhookSignature(body, validSig), true);
    assert.equal(
      federation.verifyGitHubWebhookSignature(body, "sha256=0000000000"),
      false
    );

    const state = config.loadState();
    state.apps["demo-saas"] = {
      name: "demo-saas",
      repoUrl: "https://github.com/acme/demo-saas.git",
      branch: "main",
      localPort: 4001,
      internalPort: 3000,
      containerName: "paasmcp-demo-saas",
      appDir: path.join(tempRoot, "apps", "demo-saas"),
      runtimeType: "nodejs",
      databases: [],
      domains: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    config.saveState(state);

    const whResult = await federation.handleGitHubPushWebhook(JSON.parse(body));
    assert.deepEqual(whResult.matchedApps, ["demo-saas"]);
    assert.deepEqual(whResult.rebuiltApps, ["demo-saas"]);
  });

  await t.test("6. Performs Multi-Server HA Handshake and Encrypted Vault/State Sync", () => {
    const invite = federation.generateFederationJoinToken({
      endpointUrl: "https://paas.example.com",
      mode: "active-active-tunnel",
    });
    assert.ok(invite.joinToken.startsWith("paasmcp-join://"));

    const verified = federation.parseAndVerifyFederationJoinToken(invite.joinToken);
    assert.equal(verified.endpointUrl, "https://paas.example.com");
    assert.equal(verified.mode, "active-active-tunnel");

    // Tampered token must fail HMAC verification
    assert.throws(() =>
      federation.parseAndVerifyFederationJoinToken(invite.joinToken + "tamper")
    );

    // Export and re-import encrypted sync bundle
    const bundle = federation.buildEncryptedFederationSyncBundle();
    assert.ok(bundle.appsCount >= 1);

    const applied = federation.applyEncryptedFederationSyncBundle(
      bundle.encryptedBase64,
      bundle.hmacSignature
    );
    // Our own app is never overwritten by a peer's copy of it.
    assert.ok(applied.skippedConflicts.includes("demo-saas"));
    assert.ok(!applied.importedApps.includes("demo-saas"));

    // On a server that does not have it, the app is imported and marked with its origin.
    const st = config.loadState();
    const original = st.apps["demo-saas"];
    delete st.apps["demo-saas"];
    st.apps["local-other"] = { ...original, name: "local-other" }; // takes the same port
    config.saveState(st);
    const again = federation.applyEncryptedFederationSyncBundle(bundle.encryptedBase64, bundle.hmacSignature);
    assert.ok(again.importedApps.includes("demo-saas"));
    const imported = config.loadState().apps["demo-saas"];
    assert.ok(imported.originNodeId);
    assert.notEqual(imported.localPort, original.localPort, "port clash with a local app is remapped");
    const cleanup = config.loadState();
    delete cleanup.apps["local-other"];
    config.saveState(cleanup);
  });

  const guard = await import("./guard.js");

  await t.test("7. Classifies risky actions and forbids the unsafe ones", () => {
    assert.equal(guard.assessRisk("app.expose", { appName: "blog", mode: "tailscale" }), null);
    assert.equal(guard.assessRisk("app.expose", { appName: "blog", mode: "public" })?.level, "confirm");
    assert.equal(guard.assessRisk("app.purge", { appName: "blog" })?.level, "strong");
    assert.equal(guard.assessRisk("app.trust", { appName: "blog" })?.level, "strong");
    assert.throws(
      () => guard.assessRisk("app.expose", { appName: "paasmcp-dashboard", mode: "public" }),
      guard.ForbiddenActionError
    );
    assert.equal(
      guard.assessRisk("app.expose", { appName: "paasmcp-dashboard", mode: "zero-trust" })?.level,
      "confirm"
    );
  });

  await t.test("8. Agents need a person's approval, bound to the exact parameters and usable once", () => {
    const params = { appName: "blog" };
    let approvalId = "";
    try {
      guard.authorizeAgent("app.destroy", params);
      assert.fail("should require confirmation");
    } catch (err) {
      assert.ok(err instanceof guard.ConfirmationRequiredError);
      approvalId = (err as InstanceType<typeof guard.ConfirmationRequiredError>).approvalId!;
    }
    // Same request again reuses the pending id instead of piling up requests.
    assert.throws(() => guard.authorizeAgent("app.destroy", params), (e: unknown) =>
      (e as { approvalId?: string }).approvalId === approvalId
    );
    // Not approved yet: still blocked.
    assert.throws(() => guard.authorizeAgent("app.destroy", params, approvalId));

    guard.decideApproval(approvalId, true, "test-person");
    // Approval does not carry over to other parameters...
    assert.throws(() => guard.authorizeAgent("app.destroy", { appName: "other" }, approvalId));
    // ...works once for the exact call...
    guard.authorizeAgent("app.destroy", params, approvalId);
    // ...and cannot be replayed.
    assert.throws(() => guard.authorizeAgent("app.destroy", params, approvalId));

    // Strong confirmations need the name typed by the person.
    let strongId = "";
    try {
      guard.authorizeAgent("app.purge", params);
    } catch (err) {
      strongId = (err as { approvalId: string }).approvalId;
    }
    assert.throws(() => guard.decideApproval(strongId, true, "test-person"));
    assert.throws(() => guard.decideApproval(strongId, true, "test-person", "wrong"));
    guard.decideApproval(strongId, true, "test-person", "blog");
    guard.authorizeAgent("app.purge", params, strongId);

    // People confirm directly.
    assert.throws(() => guard.authorizeHuman("app.purge", params, { confirmed: true, by: "t" }));
    guard.authorizeHuman("app.purge", params, { confirmed: true, confirmName: "blog", by: "t" });
    guard.authorizeHuman("app.expose", { appName: "blog", mode: "tailscale" }, { by: "t" });
  });

  await t.test("9. Destroy moves the app to the trash; purge deletes it", () => {
    const appDir = path.join(tempRoot, "apps", "trash-me");
    fs.mkdirSync(appDir, { recursive: true });
    fs.writeFileSync(path.join(appDir, "compose.yaml"), "services: {}\n");
    const state = config.loadState();
    state.apps["trash-me"] = {
      ...state.apps["demo-saas"],
      name: "trash-me",
      containerName: "paasmcp-trash-me",
      appDir,
    };
    config.saveState(state);

    deployer.manageAppLifecycle("trash-me", "destroy");
    const trashed = config.loadState().apps["trash-me"];
    assert.ok(trashed.trashedAt && trashed.trashDir);
    assert.equal(fs.existsSync(appDir), false);
    assert.ok(fs.existsSync(path.join(trashed.trashDir!, "compose.yaml")));
    assert.throws(() => deployer.manageAppLifecycle("trash-me", "restart"), /trash/);

    // Not expired yet: kept. 31 days later: purged.
    assert.deepEqual(deployer.purgeExpiredTrash(), []);
    assert.equal(deployer.purgeExpiredTrash(Date.now() + 31 * 24 * 3600 * 1000).length, 1);
    assert.equal(config.loadState().apps["trash-me"], undefined);
    assert.equal(fs.existsSync(trashed.trashDir!), false);
  });

  await t.test("10. Deleting a secret keeps the old value in the deleted archive", () => {
    vault.setSecretEntries("demo-app", { TO_DROP: "old-value" });
    assert.equal(vault.deleteSecretKey("demo-app", "TO_DROP"), true);
    assert.equal(vault.getSecrets("demo-app").TO_DROP, undefined);
    const archived = Object.entries(vault.getSecrets("demo-app", ".deleted"));
    assert.ok(archived.some(([k, v]) => k.startsWith("TO_DROP@") && v === "old-value"));
  });

  await t.test("11. State lock serializes operations and recovers from a dead holder", async () => {
    let counter = 0;
    const bump = () =>
      config.withStateLock(async () => {
        const before = counter;
        await new Promise((r) => setTimeout(r, 5));
        counter = before + 1;
      });
    await Promise.all([bump(), bump(), bump(), bump()]);
    assert.equal(counter, 4);

    // A lock left by a process that no longer exists is taken over.
    const lockPath = path.join(tempRoot, "paasmcp", ".lock");
    fs.writeFileSync(lockPath, JSON.stringify({ pid: 2 ** 22 + 12345, host: os.hostname(), at: Date.now() }));
    assert.equal(await config.withStateLock(() => "ok", 2000), "ok");
    assert.equal(fs.existsSync(lockPath), false);
  });

  const totp = await import("./totp.js");
  const tokens = await import("./tokens.js");
  const mcpServer = await import("./mcp-server.js");
  const mcpHttp = await import("./mcp-http.js");
  const dashboard = await import("./dashboard.js");

  await t.test("12. TOTP matches the RFC 6238 test vectors", () => {
    const secret = totp.base32Encode(Buffer.from("12345678901234567890"));
    assert.equal(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert.equal(totp.totpCode(secret, 59_000), "287082");
    assert.equal(totp.totpCode(secret, 1111111109_000), "081804");
    assert.equal(totp.verifyTotp(secret, "081804", 1111111109_000 + 30_000), true); // one step of drift
    assert.equal(totp.verifyTotp(secret, "081804", 1111111109_000 + 90_000), false);
    assert.throws(() => totp.enableDashboardTwoFactor(secret, "000000"));
  });

  await t.test("13. Personal tokens: hashed, leveled, revocable", () => {
    const { token, record } = tokens.createToken("laptop", "read");
    assert.match(token, /^pmcp_[0-9a-f]{8}_/);
    assert.equal(tokens.verifyToken(token)?.level, "read");
    assert.equal(tokens.verifyToken(token + "x"), null);
    assert.equal(JSON.stringify(tokens.listTokens()).includes(token.split("_")[2]), false);
    assert.equal(tokens.levelAllows("deploy", "read"), true);
    assert.equal(tokens.levelAllows("deploy", "destroy"), false);
    assert.equal(tokens.revokeToken(record.id), true);
    assert.equal(tokens.verifyToken(token), null);
  });

  await t.test("14. MCP enforces token levels before confirmations", async () => {
    const text = (r: { content: { text: string }[] }) => r.content[0].text;
    const readDeploy = await mcpServer.handleToolCall("paas_app_deploy", { appName: "x", repoSource: "/x" }, "read");
    assert.match(text(readDeploy as never), /read-only tools/);
    const deployDestroy = await mcpServer.handleToolCall("paas_app_lifecycle", { appName: "demo-saas", action: "destroy" }, "deploy");
    assert.match(text(deployDestroy as never), /level 'destroy'/);
    const destroyDestroy = await mcpServer.handleToolCall("paas_app_lifecycle", { appName: "demo-saas", action: "destroy" }, "destroy");
    assert.equal(JSON.parse(text(destroyDestroy as never)).confirmationRequired, true);
  });

  await t.test("15. MCP over HTTP: loopback/Tailscale only, bearer token required, tools filtered by level", async () => {
    assert.equal(mcpHttp.isAllowedMcpBindHost("127.0.0.1"), true);
    assert.equal(mcpHttp.isAllowedMcpBindHost("100.101.102.103"), true);
    assert.equal(mcpHttp.isAllowedMcpBindHost("0.0.0.0"), false);
    assert.equal(mcpHttp.isAllowedMcpBindHost("8.8.8.8"), false);
    assert.throws(() => mcpHttp.startMcpHttpServer(0, "0.0.0.0"), guard.ForbiddenActionError);

    const srv = mcpHttp.startMcpHttpServer(0, "127.0.0.1");
    await new Promise((r) => srv.once("listening", r));
    const port = (srv.address() as { port: number }).port;
    const call = (body: unknown, token?: string) =>
      fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
      });
    try {
      assert.equal((await call({ jsonrpc: "2.0", id: 1, method: "tools/list" })).status, 401);
      const { token } = tokens.createToken("reader", "read");
      const res = await call({ jsonrpc: "2.0", id: 1, method: "tools/list" }, token);
      assert.equal(res.status, 200);
      const names = ((await res.json()) as { result: { tools: { name: string }[] } }).result.tools.map((x) => x.name);
      assert.ok(names.includes("paas_system_status"));
      assert.equal(names.includes("paas_app_deploy"), false);
    } finally {
      srv.close();
    }
  });

  await t.test("16. Dashboard: public only with 2FA; with 2FA the token alone never logs in", async () => {
    assert.throws(
      () => guard.assessRisk("app.expose", { appName: "paasmcp-dashboard", mode: "public" }),
      guard.ForbiddenActionError
    );
    const dashToken = dashboard.getOrCreateDashboardToken();
    const secret = totp.newTotpSecret();
    totp.enableDashboardTwoFactor(secret, totp.totpCode(secret));
    assert.equal(guard.assessRisk("app.expose", { appName: "paasmcp-dashboard", mode: "public" })?.level, "strong");

    const srv = dashboard.startDashboardServer(0, "127.0.0.1");
    await new Promise((r) => srv.once("listening", r));
    const base = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;
    const login = (body: unknown) =>
      fetch(`${base}/api/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    try {
      assert.equal((await login({ token: dashToken })).status, 401);
      assert.equal((await fetch(`${base}/api/approvals`, { headers: { Authorization: `Bearer ${dashToken}` } })).status, 401);
      const ok = await login({ token: dashToken, code: totp.totpCode(secret) });
      assert.equal(ok.status, 200);
      const cookie = (ok.headers.get("set-cookie") || "").split(";")[0];
      assert.match(cookie, /^paasmcp_session=/);
      assert.equal((await fetch(`${base}/api/approvals`, { headers: { cookie } })).status, 200);
      assert.equal((await fetch(`${base}/api/approvals`, { headers: { cookie: "paasmcp_session=99999999999999.bad" } })).status, 401);
    } finally {
      srv.close();
    }
  });

  await t.test("17. S3 Signature V4 matches the AWS documented example", async () => {
    const backup = await import("./backup.js");
    const headers = {
      host: "examplebucket.s3.amazonaws.com",
      range: "bytes=0-9",
      "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "x-amz-date": "20130524T000000Z",
    };
    const auth = backup.signV4({
      method: "GET",
      url: new URL("https://examplebucket.s3.amazonaws.com/test.txt"),
      headers,
      payloadHash: headers["x-amz-content-sha256"],
      accessKeyId: "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      region: "us-east-1",
      amzDate: "20130524T000000Z",
    });
    assert.match(auth, /Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41$/);
    assert.match(auth, /SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,/);
  });

  await t.test("18. Volume backups, restore test, off-site sync, safe pruning and fetch", async () => {
    const backup = await import("./backup.js");
    const http = await import("node:http");
    const store = new Map<string, Buffer>();
    const srv = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks);
        const signed = /^AWS4-HMAC-SHA256 Credential=AK\//.test(String(req.headers.authorization));
        const hashOk = req.headers["x-amz-content-sha256"] === crypto.createHash("sha256").update(body).digest("hex");
        if (!signed || !hashOk) return res.writeHead(403).end("bad signature");
        if (req.method === "PUT") store.set(req.url!, body);
        const found = store.get(req.url!);
        if (req.method === "GET" && !found) return res.writeHead(404).end();
        res.writeHead(200).end(req.method === "GET" ? found : undefined);
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const vols = backup.backupAppVolumes("vol-app");
      assert.equal(vols.length, 1);
      assert.equal(vols[0].engine, "volume");
      assert.equal(backup.testRestore(vols[0].id).ok, true);
      assert.equal(database.restoreDatabase(vols[0].id).restored, true);

      // Without off-site config, pruning keeps everything.
      assert.deepEqual(backup.pruneLocalBackups(0).pruned, []);
      await assert.rejects(backup.syncOffsite(), /not configured/);

      vault.setSecretEntries("system", {
        BACKUP_S3_ENDPOINT: `http://127.0.0.1:${(srv.address() as { port: number }).port}`,
        BACKUP_S3_BUCKET: "bk",
        BACKUP_S3_ACCESS_KEY_ID: "AK",
        BACKUP_S3_SECRET_ACCESS_KEY: "SK",
        BACKUP_S3_PREFIX: "srv1",
      });
      const sync = await backup.syncOffsite();
      assert.deepEqual(sync.failed, []);
      assert.ok(sync.uploaded.includes(vols[0].id));
      assert.ok(store.has(`/bk/srv1/${vols[0].id}.enc.bak.json`));
      assert.equal((await backup.syncOffsite()).uploaded.length, 0, "second sync uploads nothing new");

      const pruned = backup.pruneLocalBackups(0, Date.now() + 1000);
      assert.ok(pruned.pruned.includes(vols[0].id));
      assert.equal(fs.existsSync(vols[0].filePath), false);
      assert.throws(() => backup.testRestore(vols[0].id), /backup fetch/);

      const fetched = await backup.fetchOffsite(vols[0].id);
      assert.equal(fetched.sha256, vols[0].sha256);
      assert.equal(backup.testRestore(vols[0].id).ok, true);
    } finally {
      srv.close();
    }
  });

  await t.test("19. Storage: Garage bucket + key per app, layout once, idempotent", async () => {
    const storage = await import("./storage.js");
    const http = await import("node:http");
    const calls: string[] = [];
    const buckets = new Map<string, string>();
    let layout = { version: 0, roles: [] as { id: string }[] };
    let token = "";
    const srv = http.createServer((req, res) => {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        if (req.headers.authorization !== `Bearer ${token}`) return res.writeHead(403).end();
        const url = new URL(req.url!, "http://x");
        const body = raw ? JSON.parse(raw) : undefined;
        calls.push(`${req.method} ${url.pathname}`);
        const json = (o: unknown, code = 200) => res.writeHead(code, { "Content-Type": "application/json" }).end(JSON.stringify(o));
        if (url.pathname === "/v1/status") return json({ node: "node1" });
        if (url.pathname === "/v1/layout" && req.method === "GET") return json(layout);
        if (url.pathname === "/v1/layout") return json({});
        if (url.pathname === "/v1/layout/apply") {
          assert.equal(body.version, layout.version + 1);
          layout = { version: body.version, roles: [{ id: "node1" }] };
          return json({});
        }
        if (url.pathname === "/v1/bucket" && req.method === "GET") {
          const id = buckets.get(url.searchParams.get("globalAlias")!);
          return id ? json({ id }) : json({ code: "NoSuchBucket" }, 404);
        }
        if (url.pathname === "/v1/bucket") {
          buckets.set(body.globalAlias, "b-" + body.globalAlias);
          return json({ id: "b-" + body.globalAlias });
        }
        if (url.pathname === "/v1/key") return json({ accessKeyId: "GK123", secretAccessKey: "sec" });
        if (url.pathname === "/v1/bucket/allow") {
          assert.deepEqual(body.permissions, { read: true, write: true, owner: false });
          return json({});
        }
        json({}, 404);
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    process.env.PAASMCP_GARAGE_ADMIN_URL = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;
    try {
      vault.setSecretEntries("system", { GARAGE_ADMIN_TOKEN: "adm" });
      token = "adm";
      const first = await storage.provisionStorage("Fotos App");
      assert.equal(first.reused, false);
      assert.equal(first.record.bucket, "app-fotos-app");
      const env = vault.getSecrets("fotos-app");
      assert.equal(env.S3_ENDPOINT, "http://paasmcp-garage:3900");
      assert.equal(env.AWS_SECRET_ACCESS_KEY, "sec");
      assert.equal(layout.version, 1);

      const second = await storage.provisionStorage("fotos-app");
      assert.equal(second.reused, true);
      assert.equal(calls.filter((c) => c === "POST /v1/key").length, 1, "no second key");
      await storage.ensureGarage();
      assert.equal(calls.filter((c) => c === "POST /v1/layout/apply").length, 1, "layout applied once");
      assert.equal(storage.listStorage().length, 1);
    } finally {
      srv.close();
      delete process.env.PAASMCP_GARAGE_ADMIN_URL;
    }
  });

  await t.test("20. Mirror: encrypted one-hour token, copy recorded, promotion needs strong approval and raises the epoch", async () => {
    const mirror = await import("./mirror.js");
    const mcp = await import("./mcp-server.js");
    const offer = await mirror.offerMirror({ peerName: "server-b", peerCidr: "100.64.0.2", advertiseHost: "100.64.0.1", withBackups: false });
    assert.match(offer.token, /^pmirror_/);
    assert.equal(config.loadState().mirror?.bindIp, "100.64.0.1");
    assert.equal(config.loadState().mirror?.offers["server-b"].peerCidr, "100.64.0.2/32");
    await assert.rejects(mirror.offerMirror({ peerName: "x", peerCidr: "1.2.3.4; rm -rf /", advertiseHost: "h" }), /Invalid --peer-ip/);

    const accepted = mirror.acceptMirror(offer.token);
    assert.equal(accepted.replica.container, `paasmcp-mirror-${accepted.replica.peerName}`);
    assert.throws(() => mirror.acceptMirror(offer.token.slice(0, -4) + "AAAA"), /could not be decrypted/);

    // An app imported from that peer gets its DATABASE_URL pointed at the local copy on promotion.
    const st = config.loadState();
    st.apps["peer-app"] = { ...Object.values(st.apps)[0], name: "peer-app", originNodeId: accepted.replica.peerNodeId, domains: [], repoUrl: "o/r" };
    config.saveState(st);
    vault.setSecretEntries("peer-app", { DATABASE_URL: "postgresql://u:p@paasmcp-postgres:5432/db_peer_app" });

    const peer = accepted.replica.peerName;
    const asked = JSON.parse((await mcp.handleToolCall("paas_mirror", { action: "promote", peer }, "destroy")).content[0].text);
    assert.equal(asked.confirmationRequired, true);
    assert.equal(asked.level, "strong");
    assert.throws(() => guard.decideApproval(asked.approvalId, true, "test", "wrong-name"));
    guard.decideApproval(asked.approvalId, true, "test", peer);
    const done = JSON.parse(
      (await mcp.handleToolCall("paas_mirror", { action: "promote", peer, approvalId: asked.approvalId }, "destroy")).content[0].text
    );
    assert.equal(done.epoch, 1);
    // (in this single-process test every imported app shares one origin, so only check ours)
    assert.deepEqual(done.apps.find((a: { app: string }) => a.app === "peer-app"), { app: "peer-app", ok: true, detail: "running here" });
    assert.equal(vault.getSecrets("peer-app").DATABASE_URL, `postgresql://u:p@paasmcp-mirror-${peer}:5432/db_peer_app`);
    await assert.rejects(mirror.promoteMirror(peer), /already promoted/);
  });

  await t.test("21. Arbiter: third vote, epochs only go up, fencing stops a server whose data moved", async () => {
    const arbiter = await import("./arbiter.js");
    const mirror = await import("./mirror.js");
    const st: import("./arbiter.js").ArbiterState = { nodes: {}, owners: {} };
    const t0 = 1_000_000;
    arbiter.arbiterDecide(st, { op: "heartbeat", node: "A", epoch: 0 }, t0);
    assert.equal(arbiter.arbiterDecide(st, { op: "claim", node: "B", epoch: 1, dataOf: "A" }, t0 + 10_000).granted, false, "A is alive for the arbiter");
    assert.equal(arbiter.arbiterDecide(st, { op: "claim", node: "B", epoch: 0, dataOf: "A" }, t0 + 120_000).granted, false, "epoch must go up");
    assert.equal(arbiter.arbiterDecide(st, { op: "claim", node: "B", epoch: 1, dataOf: "A" }, t0 + 120_000).granted, true);
    assert.equal(arbiter.arbiterDecide(st, { op: "handover", node: "A", epoch: 2, dataOf: "A", to: "A" }, t0 + 130_000).granted, false, "only the owner hands back");
    assert.equal(arbiter.arbiterDecide(st, { op: "handover", node: "B", epoch: 2, dataOf: "A", to: "A" }, t0 + 130_000).granted, true);
    assert.deepEqual(st.owners.A, { owner: "A", epoch: 2 });

    // Guard: automatic failover is forbidden without an arbiter, strong with one.
    assert.throws(() => guard.assessRisk("mirror.auto", { peer: "x" }), guard.ForbiddenActionError);
    assert.equal(guard.assessRisk("mirror.auto", { peer: "x", arbiterUrl: "http://100.64.0.9:4097" })?.level, "strong");

    // Over HTTP: bad signatures are refused; another server claiming this one fences it.
    const key = arbiter.deriveArbiterKey();
    const srv = arbiter.startArbiterServer({ port: 0, host: "127.0.0.1", key, stateFile: path.join(tempRoot, "arb.json") });
    await new Promise((r) => srv.once("listening", r));
    const url = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;
    try {
      assert.equal((await fetch(`${url}/arbiter`, { method: "POST", body: "{}", headers: { "X-Paasmcp-Signature": "00" } })).status, 401);
      const me = config.loadState().federation?.nodeId || "primary";
      const claim = await arbiter.askArbiter(url, { op: "claim", node: "other-server", epoch: 5, dataOf: me });
      assert.equal(claim.granted, true, "this server never heartbeated, so it counts as gone");
      const st2 = config.loadState();
      st2.mirror = { ...st2.mirror!, arbiterUrl: url };
      config.saveState(st2);
      const tick = await mirror.watchTick();
      assert.deepEqual((tick.fenced as { by: string }).by, "other-server");
      assert.equal(config.loadState().mirror?.fenced?.epoch, 5);
      await assert.rejects(() => deployer.deployApp({ appName: "fresh-app", repoSource: "/tmp" }), /fenced/);
      // Dashboard check: health probe, right key, wrong key, nothing listening, bad address.
      assert.deepEqual(await (await fetch(`${url}/health`)).json(), { ok: true, service: "paasmcp-arbiter" });
      const good = await mirror.checkArbiter(`${url}/arbiter`);
      assert.equal(good.ok, true);
      assert.equal(good.url, url, "a pasted /arbiter suffix is dropped");
      assert.ok(good.nodes?.some((n) => n.isMe && n.secondsAgo === 0));
      const other = arbiter.startArbiterServer({ port: 0, host: "127.0.0.1", key: "0".repeat(64), stateFile: path.join(tempRoot, "arb2.json") });
      await new Promise((r) => other.once("listening", r));
      const otherPort = (other.address() as { port: number }).port;
      assert.equal((await mirror.checkArbiter(`http://127.0.0.1:${otherPort}`)).errorCode, "badKey");
      other.close();
      await new Promise((r) => other.once("close", r));
      assert.equal((await mirror.checkArbiter(`http://127.0.0.1:${otherPort}`)).errorCode, "unreachable");
      assert.equal((await mirror.checkArbiter("ftp://x; rm")).errorCode, "badUrl");
      assert.equal((await mirror.checkArbiter()).url, url, "falls back to the saved address");
      assert.equal(mirror.setArbiterUrl(`${url}/`).arbiterUrl, url);
      assert.throws(() => mirror.setArbiterUrl("100.64.0.9:4097"), /Invalid arbiter URL/);
      assert.throws(() => arbiter.installArbiterService({ host: "tailscale", port: 4097, key: "short" }), /64-character/);
    } finally {
      srv.close();
      const st3 = config.loadState();
      delete st3.mirror!.fenced;
      delete st3.mirror!.arbiterUrl;
      config.saveState(st3);
    }
  });

  await t.test("22. Email relay: per-app variables, SMTP client never sends the password in clear", async () => {
    const email = await import("./email.js");
    const net = await import("node:net");
    assert.throws(() => email.provisionEmail("mail-app"), /No email relay/);
    assert.throws(() => email.setEmailRelay({ host: "smtp.x.com;rm", port: 587, user: "u", password: "p", fromDomain: "x.com" }));
    email.setEmailRelay({ host: "127.0.0.1", port: 2525, user: "login@x.com", password: "p@ss:w/rd", fromDomain: "example.com", apiKey: "xkeysib-1" });
    const out = email.provisionEmail("Mail App", 'Guarapps "Bot"');
    assert.equal(out.from, "Guarapps Bot <mail-app@example.com>");
    const env = vault.getSecrets("mail-app");
    assert.equal(env.SMTP_SECURE, "starttls");
    assert.equal(env.EMAIL_URL, "submission://login%40x.com:p%40ss%3Aw%2Frd@127.0.0.1:2525");
    assert.equal(env.BREVO_API_KEY, "xkeysib-1");

    const seen: string[] = [];
    const srv = net.createServer((c) => {
      let inData = false;
      let buf = "";
      c.write("220 fake ESMTP\r\n");
      c.on("data", (d) => {
        buf += d.toString();
        let i;
        while ((i = buf.indexOf("\r\n")) >= 0) {
          const line = buf.slice(0, i);
          buf = buf.slice(i + 2);
          seen.push(line);
          if (inData) {
            if (line === ".") {
              inData = false;
              c.write("250 2.0.0 queued as ABC\r\n");
            }
            continue;
          }
          if (line.startsWith("EHLO")) c.write("250-fake\r\n250 AUTH PLAIN\r\n");
          else if (line.startsWith("AUTH PLAIN")) c.write("235 ok\r\n");
          else if (line.startsWith("MAIL") || line.startsWith("RCPT")) c.write("250 ok\r\n");
          else if (line === "DATA") {
            inData = true;
            c.write("354 go\r\n");
          } else if (line === "QUIT") c.end("221 bye\r\n");
        }
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const relay = { ...email.getEmailRelay()!, port: (srv.address() as { port: number }).port };
    try {
      await assert.rejects(email.sendTestEmail("me@example.org", { relay }), /refusing to send the password in clear/);
      assert.ok(!seen.some((l) => l.startsWith("AUTH")), "no AUTH without TLS");
      const sent = await email.sendTestEmail("me@example.org", { relay, allowPlaintextForLocalTest: true });
      assert.match(sent.accepted, /queued as ABC/);
      const auth = seen.find((l) => l.startsWith("AUTH PLAIN "))!.slice(11);
      assert.equal(Buffer.from(auth, "base64").toString(), "\0login@x.com\0p@ss:w/rd");
      assert.ok(seen.includes("RCPT TO:<me@example.org>"));
      assert.ok(!sent.log.join(" ").includes(auth), "password not in the log");
      await assert.rejects(email.sendTestEmail("bad address", { relay }), /Invalid recipient/);
    } finally {
      srv.close();
    }
  });

  await t.test("23. Updater: same-major only, newest pick, existing installs keep their image until updated", async () => {
    const up = await import("./updater.js");
    const mcp = await import("./mcp-server.js");
    assert.equal(up.majorOf("postgres", "postgres:16.15-alpine"), "16");
    assert.equal(up.majorOf("postgres", "postgres:16-alpine"), "16");
    assert.equal(up.majorOf("redis", "redis:7.4.12-alpine"), "7.4");
    assert.equal(up.majorOf("garage", "dxflrs/garage:v1.1.0"), "v1");
    assert.equal(up.pickLatest("postgres", "postgres:16.9-alpine", ["16.10-alpine", "16.2-alpine", "17.1-alpine", "16.11-bookworm", "16.11-alpine"]), "postgres:16.11-alpine");
    assert.equal(up.pickLatest("garage", "dxflrs/garage:v1.1.0", ["v1.3.1", "v1.99.3-internal", "v2.5.0", "v1.0.0"]), "dxflrs/garage:v1.3.1");
    assert.equal(up.pickLatest("redis", "redis:7.4.12-alpine", ["7.4.3-alpine", "7.2.9-alpine"]), null);

    // An older install keeps the image its compose file already runs.
    const pgDir = path.join(tempRoot, "paasmcp-postgres");
    fs.mkdirSync(pgDir, { recursive: true });
    fs.writeFileSync(path.join(pgDir, "compose.yaml"), "services:\n  postgres:\n    image: postgres:16-alpine\n");
    assert.equal(up.imageFor("postgres"), "postgres:16-alpine");

    const found = await up.checkUpdates(async (repo) => (repo === "library/postgres" ? ["16.15-alpine", "17.2-alpine"] : []));
    assert.equal(found.find((f) => f.component === "postgres")?.available, "postgres:16.15-alpine");

    assert.throws(() => up.applyUpdate("postgres", "postgres:17.2-alpine"), /major upgrade/);
    assert.throws(() => up.applyUpdate("postgres", "evil/postgres:16.15-alpine"), /not an image of/);

    const asked = JSON.parse((await mcp.handleToolCall("paas_update", { action: "apply", component: "postgres", image: "postgres:16.15-alpine" }, "destroy")).content[0].text);
    assert.equal(asked.confirmationRequired, true);
    guard.decideApproval(asked.approvalId, true, "test");
    const done = JSON.parse(
      (await mcp.handleToolCall("paas_update", { action: "apply", component: "postgres", image: "postgres:16.15-alpine", approvalId: asked.approvalId }, "destroy")).content[0].text
    );
    assert.equal(done.to, "postgres:16.15-alpine");
    assert.equal(up.imageFor("postgres"), "postgres:16.15-alpine");
  });

  await t.test("24. Generated Dockerfiles per language (fixtures in test/fixtures)", () => {
    const fixtures = path.resolve("test/fixtures");
    const cases: [string, string, number, RegExp[]][] = [
      ["node", "nodejs", 3000, [/CMD \["node", "server.js"\]/, /ENV PORT=3000/]],
      ["vite", "nodejs-static-spa", 80, [/COPY --from=builder \/app\/dist /]],
      ["cra", "nodejs-static-spa", 80, [/COPY --from=builder \/app\/build /]],
      ["fastapi", "python", 8000, [/"uvicorn", "main:app"/]],
      ["django", "python", 8000, [/"gunicorn", "-b", "0.0.0.0:8000", "site1.wsgi"/, /pip install --no-cache-dir gunicorn/]],
      ["go", "go", 8080, [/go build -o \/app\/server \.$/m]],
      ["go-cmd", "go", 8080, [/go build -o \/app\/server \.\/cmd\/server/]],
      ["static", "static-html", 80, [/FROM nginx:alpine/]],
    ];
    for (const [dir, runtime, port, patterns] of cases) {
      const work = fs.mkdtempSync(path.join(tempRoot, `fx-${dir}-`));
      fs.cpSync(path.join(fixtures, dir), work, { recursive: true });
      const plan = github.detectOrGenerateDockerfile(work, dir === "vite" || dir === "static" ? 9999 : undefined);
      assert.equal(plan.runtimeType, runtime, dir);
      assert.equal(plan.detectedPort, port, `${dir} port (nginx always 80)`);
      const df = fs.readFileSync(path.join(work, plan.dockerfilePath), "utf-8");
      for (const re of patterns) assert.match(df, re, `${dir}: ${re}`);
    }
  });

  await t.test("25. Git polling: redeploys only when the branch moved; opt-in per git app", async () => {
    const poller = await import("./poller.js");
    const st = config.loadState();
    st.apps["poll-app"] = { ...Object.values(st.apps)[0], name: "poll-app", repoUrl: "o/r", branch: "main", lastCommit: "abc1234", domains: [], originNodeId: undefined };
    st.apps["local-app"] = { ...st.apps["poll-app"], name: "local-app", repoUrl: tempRoot };
    config.saveState(st);
    assert.throws(() => poller.setPolling("local-app", true), /not deployed from a git repository/);
    poller.setPolling("poll-app", true);
    const same = await poller.pollRepos(() => "abc1234" + "0".repeat(33));
    assert.deepEqual(same.checked, ["poll-app"]);
    assert.deepEqual(same.deployed, []);
    assert.deepEqual(same.errors, []);
    // A new commit triggers a deploy (it fails here because o/r cannot be cloned, which proves it tried).
    const moved = await poller.pollRepos(() => "f".repeat(40));
    assert.equal(moved.errors[0]?.app, "poll-app");
    poller.setPolling("poll-app", false);
    assert.deepEqual((await poller.pollRepos(() => "f".repeat(40))).checked, []);
  });

  await t.test("26. Blue/green deploy: healthcheck probe, path validation, pinned primary image", async () => {
    const http = await import("node:http");
    // The probe passes on the first status below 500 (5xx means "keep waiting"; redirects are not followed).
    let hits = 0;
    const srv = http.createServer((req, res) => {
      hits++;
      if (req.url === "/redirect") {
        res.writeHead(302, { Location: "http://203.0.113.1/" });
        return res.end();
      }
      res.writeHead(hits < 3 ? 503 : 200);
      res.end("ok");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const base = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;
    try {
      const ok = await deployer.waitForHealthy({ url: `${base}/healthz`, timeoutMs: 5000, intervalMs: 20 });
      assert.equal(ok.healthy, true);
      assert.equal(ok.status, 200);
      assert.equal(hits, 3);
      const redirect = await deployer.waitForHealthy({ url: `${base}/redirect`, timeoutMs: 2000, intervalMs: 20 });
      assert.equal(redirect.healthy, true);
      assert.equal(redirect.status, 302);
      const dead = await deployer.waitForHealthy({ url: `${base}/`, timeoutMs: 2000, intervalMs: 20, isAlive: () => false });
      assert.equal(dead.healthy, false);
      assert.match(dead.reason || "", /exited/);
    } finally {
      srv.close();
    }
    // Nothing listening: gives up after the timeout and says why.
    const freePort = await deployer.findFreeLoopbackPort();
    const none = await deployer.waitForHealthy({ url: `http://127.0.0.1:${freePort}/`, timeoutMs: 600, intervalMs: 50 });
    assert.equal(none.healthy, false);
    assert.match(none.reason || "", /within 1s \(last: ECONNREFUSED\)/);

    const err = new deployer.HealthcheckFailedError("demo", { healthy: false, elapsedMs: 20000, reason: "boom", path: "/" }, "Error: DATABASE_URL missing");
    assert.match(err.message, /running is untouched/);
    assert.match(err.message, /DATABASE_URL missing/);

    assert.equal(deployer.validateHealthcheckPath(undefined), undefined);
    assert.equal(deployer.validateHealthcheckPath("/api/health?full=1"), "/api/health?full=1");
    for (const bad of ["healthz", "/a b", "/x\nHost: evil", "@evil.com/", "/\u00e9"]) {
      assert.throws(() => deployer.validateHealthcheckPath(bad), /Invalid healthcheckPath/);
    }
    assert.throws(() => deployer.validateHealthcheckTimeout(0), /between 1 and 300/);
    assert.throws(() => deployer.validateHealthcheckTimeout(301), /between 1 and 300/);
    assert.equal(deployer.validateHealthcheckTimeout(45), 45);

    // Compose pass-through: a built primary service gets the fixed paasmcp/<slug>:latest tag (restore + rollback).
    const composeDir = fs.mkdtempSync(path.join(tempRoot, "bg-"));
    const composeFile = path.join(composeDir, "docker-compose.yml");
    fs.writeFileSync(composeFile, YAML.stringify({ services: { web: { build: "." }, db: { image: "postgres:16" } } }));
    const built = deployer.generateSanitizedComposeFromRepo({
      repoComposePath: composeFile, slug: "bg-app", containerName: "paasmcp-bg-app",
      localPort: 4020, internalPort: 3000, primaryServiceName: "web",
    });
    assert.equal(built.primaryImage, "paasmcp/bg-app:latest");
    assert.equal(YAML.parse(built.yaml).services.web.image, "paasmcp/bg-app:latest");
    assert.equal(YAML.parse(built.yaml).services.db.image, "postgres:16");
    fs.writeFileSync(composeFile, YAML.stringify({ services: { web: { image: "ghcr.io/acme/web:1" } } }));
    const pulled = deployer.generateSanitizedComposeFromRepo({
      repoComposePath: composeFile, slug: "bg-app", containerName: "paasmcp-bg-app",
      localPort: 4020, internalPort: 3000, primaryServiceName: "web",
    });
    assert.equal(pulled.primaryImage, "ghcr.io/acme/web:1");

    await assert.rejects(
      () => deployer.deployApp({ appName: "bg-bad", repoSource: "/tmp", healthcheckPath: "nope" }),
      /Invalid healthcheckPath/
    );
  });

  fs.rmSync(tempRoot, { recursive: true, force: true });
});
