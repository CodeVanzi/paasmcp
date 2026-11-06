import { loadState, saveState } from "./config.js";
import { manageAppLifecycle, TRASH_RETENTION_DAYS } from "./deployer.js";
import { releaseAddresses } from "./exposure.js";
import { audit } from "./guard.js";
import { sendNotice } from "./notify.js";

// The trash empties itself: an app stays there TRASH_RETENTION_DAYS days, the person gets a notice
// WARN_DAYS before, and nothing is deleted less than WARN_DAYS after that notice (so an app that was
// already old in the trash when this started is warned first, never deleted on the spot).
// Runs with the nightly backup (dashboard loop or systemd timer). PAASMCP_TRASH_AUTO=0 turns it off.

export const WARN_DAYS = 3;
const DAY = 24 * 3600 * 1000;

export interface TrashEntry {
  name: string;
  trashedAt?: string;
  trashWarnedAt?: string;
}

/** Pure (tested): who gets the notice now and who is deleted now. */
export function trashPlan(apps: TrashEntry[], now: number): { warn: string[]; purge: string[] } {
  const warn: string[] = [];
  const purge: string[] = [];
  for (const a of apps) {
    const at = a.trashedAt ? Date.parse(a.trashedAt) : NaN;
    if (!Number.isFinite(at)) continue;
    const warned = a.trashWarnedAt ? Date.parse(a.trashWarnedAt) : NaN;
    if (Number.isFinite(warned)) {
      if (now - at >= TRASH_RETENTION_DAYS * DAY && now - warned >= WARN_DAYS * DAY) purge.push(a.name);
    } else if (now - at >= (TRASH_RETENTION_DAYS - WARN_DAYS) * DAY) {
      warn.push(a.name);
    }
  }
  return { warn, purge };
}

/** When a trashed app will be deleted, for the screen (date only; at least WARN_DAYS after the notice). */
export function trashDeleteDate(a: TrashEntry): string | undefined {
  const at = a.trashedAt ? Date.parse(a.trashedAt) : NaN;
  if (!Number.isFinite(at)) return undefined;
  let when = at + TRASH_RETENTION_DAYS * DAY;
  const warned = a.trashWarnedAt ? Date.parse(a.trashWarnedAt) : NaN;
  if (Number.isFinite(warned)) when = Math.max(when, warned + WARN_DAYS * DAY);
  return new Date(when).toISOString();
}

export async function runTrashCleanup(now = Date.now()): Promise<{ warned: string[]; purged: string[]; errors: string[] }> {
  const out = { warned: [] as string[], purged: [] as string[], errors: [] as string[] };
  if (process.env.PAASMCP_TRASH_AUTO === "0") return out;
  const plan = trashPlan(Object.values(loadState().apps), now);
  for (const name of plan.warn) {
    const st = loadState();
    const app = st.apps[name];
    if (!app?.trashedAt) continue;
    app.trashWarnedAt = new Date(now).toISOString();
    saveState(st);
    const day = new Date(trashDeleteDate(app) || now).toISOString().slice(0, 10);
    await sendNotice(
      (lang) =>
        lang === "en"
          ? { title: `${name} will be deleted`, text: `🗑️ ${name} has been in the trash for a while and will be deleted for good on ${day} (its data too). To keep it, restore it on the dashboard (Your apps).` }
          : { title: `${name} será apagado`, text: `🗑️ ${name} está na lixeira há quase ${TRASH_RETENTION_DAYS} dias e será apagado de vez em ${day} (com os dados). Para manter, restaure no painel (Seus apps).` },
      "trash.warn",
      name
    );
    audit({ event: "trash.warn", app: name, deleteOn: day });
    out.warned.push(name);
  }
  for (const name of plan.purge) {
    try {
      const note = await releaseAddresses(name);
      manageAppLifecycle(name, "purge");
      audit({ event: "trash.autopurge", app: name, ...(note ? { addresses: note } : {}) });
      await sendNotice(
        (lang) =>
          lang === "en"
            ? { title: `${name} deleted`, text: `🗑️ ${name} stayed ${TRASH_RETENTION_DAYS} days in the trash and was deleted for good.` }
            : { title: `${name} apagado`, text: `🗑️ ${name} ficou ${TRASH_RETENTION_DAYS} dias na lixeira e foi apagado de vez.` },
        "trash.purged",
        name
      );
      out.purged.push(name);
    } catch (err) {
      out.errors.push(`${name}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return out;
}
