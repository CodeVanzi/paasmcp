import { HealthcheckFailedError } from "./deployer.js";

/**
 * Turns a failed deploy into a short explanation in plain words, for the dashboard.
 * The raw error still goes along ("details"); this only says what probably happened and what to do.
 */
export type DeployFailureKind =
  | "healthcheck"
  | "access"
  | "branch"
  | "stack"
  | "memory"
  | "build"
  | "network"
  | "trash"
  | "name"
  | "other";

/** Where the dashboard can send the person to fix it. */
export type DeployFailureAction = "github" | "logs" | "options" | "trash" | "guide";

export interface DeployFailure {
  kind: DeployFailureKind;
  action?: DeployFailureAction;
}

export function explainDeployError(err: unknown): DeployFailure {
  if (err instanceof HealthcheckFailedError) return { kind: "healthcheck", action: "options" };
  const msg = err instanceof Error ? err.message : String(err);
  if (/is in the trash/i.test(msg)) return { kind: "trash", action: "trash" };
  if (/already exists with other code/i.test(msg)) return { kind: "name" };
  if (/Could not resolve host|Temporary failure in name resolution|Network is unreachable|Connection timed out/i.test(msg)) {
    return { kind: "network" };
  }
  if (/Remote branch .* not found|couldn't find remote ref|pathspec .* did not match/i.test(msg)) return { kind: "branch" };
  if (
    /Repository not found|Authentication failed|could not read Username|terminal prompts disabled|Permission denied \(publickey\)|Invalid GitHub repository format|Invalid repository source/i.test(
      msg
    )
  ) {
    return { kind: "access", action: "github" };
  }
  if (/Could not auto-detect stack|add a Dockerfile/i.test(msg)) return { kind: "stack", action: "guide" };
  if (/exit 137|OOMKilled|heap out of memory|Cannot allocate memory|signal: killed/i.test(msg)) return { kind: "memory", action: "options" };
  if (/Command failed: docker (compose .*)?build|failed to solve|error building/i.test(msg)) return { kind: "build" };
  return { kind: "other" };
}
