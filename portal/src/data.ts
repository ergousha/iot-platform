// Pure data shaping: no AWS calls, so it is unit-tested (data.test.ts).

/** A DynamoDB attribute value, the subset the tables use. */
export type AttributeValue = { S?: string; N?: string; BOOL?: boolean; NULL?: boolean };
export type Item = Record<string, AttributeValue>;

export type Plain = string | number | boolean | null;

export function unmarshal(item: Item): Record<string, Plain> {
  const out: Record<string, Plain> = {};
  for (const [k, v] of Object.entries(item)) {
    if (v.S !== undefined) out[k] = v.S;
    else if (v.N !== undefined) out[k] = Number(v.N);
    else if (v.BOOL !== undefined) out[k] = v.BOOL;
    else out[k] = null;
  }
  return out;
}

/** clip keeps device-written text short; React renders it as text only. */
export function clip(value: unknown, max = 80): string {
  const s = typeof value === "string" ? value : value === undefined || value === null ? "" : JSON.stringify(value);
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

// ---- presence -------------------------------------------------------------

export interface Presence {
  online: boolean;
  lastConnected?: number; // ms
  lastDisconnected?: number; // ms
}

/**
 * presence turns the presence table (two items per thing: its latest
 * connected and disconnected events) into online state. The session
 * number orders the two, since a disconnect of an old session can arrive
 * after the next connect; the same rule as the OTA controller.
 */
export function presence(items: Record<string, Plain>[]): Map<string, Presence> {
  const byThing = new Map<string, { c?: Record<string, Plain>; d?: Record<string, Plain> }>();
  for (const it of items) {
    const thing = it.thing;
    if (typeof thing !== "string") continue;
    const e = byThing.get(thing) ?? {};
    if (it.event === "connected") e.c = it;
    else if (it.event === "disconnected") e.d = it;
    byThing.set(thing, e);
  }
  const out = new Map<string, Presence>();
  for (const [thing, { c, d }] of byThing) {
    const num = (x: Plain | undefined) => (typeof x === "number" ? x : undefined);
    const cs = num(c?.session) ?? -1;
    const ds = num(d?.session) ?? -1;
    out.set(thing, {
      online: c !== undefined && (d === undefined || cs > ds || (cs === ds && (num(c.at) ?? 0) > (num(d.at) ?? 0))),
      lastConnected: num(c?.at),
      lastDisconnected: num(d?.at),
    });
  }
  return out;
}

// ---- registry ---------------------------------------------------------------

export interface RegistryRecord {
  mac: string;
  thing: string; // MAC12
  product: string;
  allowed: boolean;
  provisioned: boolean;
  canary: boolean;
  enrolBy?: number; // unix seconds
  legacy: boolean; // written by hand before products existed: no product attribute
  via?: string; // how it enrolled: public_key or secret
  enrolledAt?: string; // RFC 3339
  raw: Record<string, Plain>;
}

/** The legacy product owns records written before products existed. */
export function registryRecord(item: Record<string, Plain>, legacyProduct: string): RegistryRecord {
  const mac = typeof item.mac_address === "string" ? item.mac_address : "";
  return {
    mac,
    thing: mac.replace(/[^0-9A-Fa-f]/g, "").toUpperCase(),
    product: typeof item.product === "string" ? item.product : legacyProduct,
    allowed: item.allowed === true,
    provisioned: item.provisioned === true,
    canary: item.canary === true,
    enrolBy: typeof item.enrol_by === "number" ? item.enrol_by : undefined,
    legacy: typeof item.product !== "string",
    via: typeof item.last_provisioned_via === "string" ? item.last_provisioned_via : undefined,
    enrolledAt: typeof item.last_provisioned_at === "string" ? item.last_provisioned_at : undefined,
    raw: item,
  };
}

export type WindowState = "open" | "expired" | "none";

/** windowState mirrors the controller: allowed, not provisioned, enrol_by ahead. */
export function windowState(r: RegistryRecord, nowMs: number): WindowState {
  if (!r.allowed || r.provisioned) return "none";
  if (r.enrolBy === undefined) return "open"; // a record without enrol_by never expires
  return r.enrolBy * 1000 > nowMs ? "open" : "expired";
}

export type Tone = "ok" | "warn" | "danger" | "info" | "neutral";

export interface Badge {
  label: string;
  tone: Tone;
  tip: string;
}

/** enrolment is a registry record's state in plain words. */
export function enrolment(r: RegistryRecord, nowMs: number): Badge {
  if (r.provisioned) {
    return {
      label: "Enrolled",
      tone: "ok",
      tip:
        "This record has enrolled its device, which now has its own certificate. A record enrols once: " +
        "enrolling again needs `ergo commission` at the bench" +
        (r.allowed ? "." : ", and allowed=false here only blocks that; the enrolled device keeps working."),
    };
  }
  const w = windowState(r, nowMs);
  if (w === "open") {
    return { label: "Window open", tone: "warn", tip: "The device may enrol now; the claim certificate is active for it." };
  }
  if (w === "expired") {
    return { label: "Window expired", tone: "neutral", tip: "The enrolment window closed before the device enrolled." };
  }
  return { label: "Not allowed", tone: "neutral", tip: "allowed=false: this record cannot enrol a device." };
}

export const enrolMethods: Record<string, string> = {
  public_key: "Secure-element key",
  secret: "Shared secret",
};

const bootReasons: Record<string, [string, Tone]> = {
  poweron: ["Power-on: switched on, or the power was cut.", "neutral"],
  ext: ["Reset by the external reset pin.", "neutral"],
  sw: ["Software restart: the firmware restarted itself, for example after an OTA update.", "neutral"],
  panic: ["Crash: the firmware panicked.", "danger"],
  int_wdt: ["Interrupt watchdog: the firmware hung with interrupts blocked.", "danger"],
  task_wdt: ["Task watchdog: a task stopped responding.", "danger"],
  wdt: ["Watchdog reset.", "danger"],
  deepsleep: ["Woke from deep sleep.", "neutral"],
  brownout: ["Brownout: the supply voltage dropped too low.", "warn"],
  sdio: ["Reset over SDIO.", "neutral"],
  usb: ["Reset over USB (flashing or a serial monitor).", "neutral"],
  jtag: ["Reset over JTAG (debugger).", "neutral"],
  efuse: ["eFuse error.", "danger"],
  pwr_glitch: ["Power glitch detected.", "warn"],
  cpu_lockup: ["CPU lockup.", "danger"],
};

/** bootReason explains the ESP32 reset reason a device reports. */
export function bootReason(code: string | undefined): Badge | undefined {
  if (!code) return undefined;
  const known = bootReasons[code];
  return {
    label: clip(code, 24),
    tone: known?.[1] ?? "neutral",
    tip: `Why the device last restarted. ${known?.[0] ?? "Unknown reset reason."}`,
  };
}

/** mode explains a product's OTA mode (the fleet attribute ota_mode). */
export function mode(value: string | undefined, soakHours: string | undefined): Badge {
  const soak = soakHours ? `${soakHours} h` : "the soak time";
  switch (value || "auto") {
    case "auto":
      return {
        label: "Automatic",
        tone: "ok",
        tip: `Each verified release goes to the canaries first, soaks for ${soak}, then the controller promotes it to the whole fleet.`,
      };
    case "hold":
      return {
        label: "On hold",
        tone: "warn",
        tip: `Releases still go to the canaries and soak for ${soak}; then the controller emails you instead of promoting.`,
      };
    case "frozen":
      return { label: "Frozen", tone: "danger", tip: "The controller leaves this product alone: no new OTA jobs." };
    default:
      return { label: clip(value, 20), tone: "neutral", tip: "An OTA mode this portal does not know." };
  }
}

/** ago is a short relative time ("5 min ago"); empty when unknown. */
export function ago(ms: number | undefined, nowMs: number): string {
  if (ms === undefined || Number.isNaN(ms)) return "";
  const s = Math.floor((nowMs - ms) / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.floor(h / 24)} days ago`;
}

// ---- controller status ------------------------------------------------------

export interface DeviceStatus {
  online: boolean;
  canary: boolean;
  fw?: string;
  boot_reason?: string;
  boot_count?: number;
  key_id?: string[];
}

export interface ProductStatus {
  product: string;
  state: Record<string, string>;
  verified_releases: string[] | null;
  refused_releases: { Version: string; Reason: string }[] | null;
  active_jobs: string[] | null;
  devices: Record<string, DeviceStatus>;
  excluded: string[] | null;
}

/** A verified release is listed as "X.Y.Z (key id)". */
export function releaseVersion(entry: string): string {
  return entry.split(" ")[0] ?? entry;
}

export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** rollbackTargets: verified versions below the fleet's, newest first. */
export function rollbackTargets(s: ProductStatus): string[] {
  const fleet = s.state.fleet_version ?? "";
  if (fleet === "") return [];
  return (s.verified_releases ?? [])
    .map(releaseVersion)
    .filter((v) => compareVersions(v, fleet) < 0)
    .sort((a, b) => compareVersions(b, a));
}

export interface ReleaseRow {
  version: string;
  key: string; // signing key id, or the refusal reason
  badge: Badge;
}

/**
 * releaseRows lists a product's releases, newest first: verified ones with
 * where they stand against the fleet, then the refused ones.
 */
export function releaseRows(s: ProductStatus): ReleaseRow[] {
  const fleet = s.state.fleet_version ?? "";
  const halted = s.state.halted_version ?? "";
  const rows: ReleaseRow[] = (s.verified_releases ?? []).map((entry) => {
    const version = releaseVersion(entry);
    const key = entry
      .slice(version.length)
      .trim()
      .replace(/^\(|\)$/g, "");
    let badge: Badge;
    if (version === halted) {
      badge = { label: "Halted", tone: "danger", tip: clip(s.state.halted_reason || "Halted on the canaries.", 300) };
    } else if (fleet !== "" && version === fleet) {
      badge = { label: "On the fleet", tone: "ok", tip: "Every device of the product is meant to run this version." };
    } else if (fleet === "" || compareVersions(version, fleet) > 0) {
      badge = { label: "Newer", tone: "info", tip: "Above the fleet version: on its way through canary and soak." };
    } else {
      badge = { label: "Older", tone: "neutral", tip: "Below the fleet version: a rollback target." };
    }
    return { version, key, badge };
  });
  rows.sort((a, b) => compareVersions(b.version, a.version));
  for (const r of s.refused_releases ?? []) {
    rows.push({
      version: clip(r.Version, 40),
      key: "",
      badge: { label: "Refused", tone: "danger", tip: `The controller will not ship it: ${clip(r.Reason, 300)}` },
    });
  }
  return rows;
}

/** Where a device sits in its product's groups. */
export type Placement = "canary" | "fleet" | "excluded";

export function placement(s: ProductStatus, thing: string): Placement {
  if ((s.excluded ?? []).includes(thing)) return "excluded";
  return s.devices[thing]?.canary ? "canary" : "fleet";
}

/**
 * move is the group change a toggle makes. A thing is in exactly one group
 * of the fleet hierarchy (fleet or its canary child), and excluded is
 * outside it.
 */
export function move(
  groups: { fleet: string; canary: string; excluded: string },
  from: Placement,
  to: Placement,
): { add: string[]; remove: string[] } {
  if (from === to) return { add: [], remove: [] };
  return { add: [groups[to]], remove: [groups[from]] };
}

// ---- audit -------------------------------------------------------------------

export interface Session {
  time: string;
  username: string;
  role: string;
  accessKeyId: string;
  sourceIp: string;
}

/** The parts of a CloudTrail record that session reads; nothing is trusted. */
interface TrailRecord {
  eventTime?: unknown;
  sourceIPAddress?: unknown;
  requestParameters?: { roleArn?: unknown; principalTags?: { username?: unknown }; tags?: unknown };
  responseElements?: { credentials?: { accessKeyId?: unknown } };
}

/**
 * session reads one CloudTrail AssumeRoleWithWebIdentity event of a portal
 * role. The identity pool passes the Cognito user name as the session tag
 * `username`.
 */
export function session(cloudTrailEvent: string | undefined): Session | undefined {
  if (!cloudTrailEvent) return undefined;
  let e: TrailRecord;
  try {
    const parsed: unknown = JSON.parse(cloudTrailEvent);
    if (typeof parsed !== "object" || parsed === null) return undefined;
    e = parsed as TrailRecord;
  } catch {
    return undefined;
  }
  const req = e.requestParameters ?? {};
  const roleArn: string = typeof req.roleArn === "string" ? req.roleArn : "";
  if (!roleArn.includes("-portal-")) return undefined;
  let user: unknown = req.principalTags?.username;
  if (user === undefined && Array.isArray(req.tags)) {
    user = (req.tags as { key?: unknown; value?: unknown }[]).find((t) => t?.key === "username")?.value;
  }
  return {
    time: String(e.eventTime ?? ""),
    username: clip(user ?? "?", 64),
    role: roleArn.slice(roleArn.lastIndexOf("/") + 1),
    accessKeyId: String(e.responseElements?.credentials?.accessKeyId ?? ""),
    sourceIp: clip(e.sourceIPAddress ?? "", 64),
  };
}
