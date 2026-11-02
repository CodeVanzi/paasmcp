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

    const sanitizedYaml = deployer.generateSanitizedComposeFromRepo({
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

  await t.test("5. Verifies GitHub Webhook HMAC-SHA256 signatures and triggers matched branch rebuilds", () => {
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

    const whResult = federation.handleGitHubPushWebhook(JSON.parse(body));
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
    assert.ok(applied.importedApps.includes("demo-saas"));
  });

  fs.rmSync(tempRoot, { recursive: true, force: true });
});
