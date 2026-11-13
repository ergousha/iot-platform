import { describe, expect, it } from "vitest";
import { parseConfig } from "./config";
import {
  ago,
  bootReason,
  clip,
  enrolment,
  mode,
  move,
  type ProductStatus,
  placement,
  presence,
  registryRecord,
  releaseRows,
  rollbackTargets,
  session,
  unmarshal,
  windowState,
} from "./data";

const status = (over: Partial<ProductStatus> = {}): ProductStatus => ({
  product: "vaktus",
  state: { ota_mode: "auto", fleet_version: "1.2.0", soak_hours: "24" },
  verified_releases: ["1.0.0 (a)", "1.1.0 (a)", "1.2.0 (a)", "1.3.0 (b)"],
  refused_releases: null,
  active_jobs: null,
  devices: { AAA: { online: true, canary: true }, BBB: { online: false, canary: false } },
  excluded: ["CCC"],
  ...over,
});

describe("presence", () => {
  it("orders by session, then time, like the controller", () => {
    const p = presence([
      { thing: "A", event: "connected", at: 2000, session: 7 },
      { thing: "A", event: "disconnected", at: 3000, session: 6 }, // late disconnect of an older session
      { thing: "B", event: "connected", at: 1000, session: 3 },
      { thing: "B", event: "disconnected", at: 2000, session: 3 },
      { thing: "C", event: "disconnected", at: 2000, session: 1 },
    ]);
    expect(p.get("A")?.online).toBe(true);
    expect(p.get("B")?.online).toBe(false);
    expect(p.get("C")?.online).toBe(false);
    expect(p.get("A")?.lastDisconnected).toBe(3000);
  });
});

describe("registry", () => {
  it("unmarshals and normalises", () => {
    const r = registryRecord(
      unmarshal({
        mac_address: { S: "38:18:2b:84:56:f4" },
        allowed: { BOOL: true },
        provisioned: { BOOL: false },
        enrol_by: { N: "100" },
      }),
    );
    expect(r.thing).toBe("38182B8456F4");
    expect(r.product).toBe(""); // no product attribute: no product (there is no legacy product)
    expect(windowState(r, 99_000)).toBe("open");
    expect(windowState(r, 100_000)).toBe("expired");
    expect(windowState({ ...r, provisioned: true }, 0)).toBe("none");
  });
});

describe("releases", () => {
  it("offers only verified versions below the fleet's, newest first", () => {
    expect(rollbackTargets(status())).toEqual(["1.1.0", "1.0.0"]);
    expect(rollbackTargets(status({ state: { fleet_version: "" } }))).toEqual([]);
  });
});

describe("groups", () => {
  it("places and moves within the product's groups", () => {
    const s = status();
    expect(placement(s, "AAA")).toBe("canary");
    expect(placement(s, "BBB")).toBe("fleet");
    expect(placement(s, "CCC")).toBe("excluded");
    const g = { fleet: "f", canary: "c", excluded: "x" };
    expect(move(g, "fleet", "canary")).toEqual({ add: ["c"], remove: ["f"] });
    expect(move(g, "excluded", "fleet")).toEqual({ add: ["f"], remove: ["x"] });
    expect(move(g, "canary", "canary")).toEqual({ add: [], remove: [] });
  });
});

describe("audit", () => {
  it("reads the username session tag of a portal role", () => {
    const ev = JSON.stringify({
      eventTime: "2026-11-12T10:00:00Z",
      sourceIPAddress: "cognito-identity.amazonaws.com",
      requestParameters: { roleArn: "arn:aws:iam::1:role/esp32-ztp-portal-owner", principalTags: { username: "ergin" } },
      responseElements: { credentials: { accessKeyId: "ASIAEXAMPLE" } },
    });
    expect(session(ev)).toMatchObject({ username: "ergin", role: "esp32-ztp-portal-owner", accessKeyId: "ASIAEXAMPLE" });
    expect(session(JSON.stringify({ requestParameters: { roleArn: "arn:aws:iam::1:role/other" } }))).toBeUndefined();
    expect(session("not json")).toBeUndefined();
  });
});

describe("text", () => {
  it("clips device-written text", () => {
    expect(clip("x".repeat(100), 10)).toHaveLength(10);
    expect(clip({ a: 1 })).toBe('{"a":1}');
    expect(clip(undefined)).toBe("");
  });
});

describe("config", () => {
  const good = {
    region: "eu-central-1",
    userPoolId: "p",
    userPoolEndpoint: "cognito-idp.eu-central-1.amazonaws.com/p",
    clientId: "c",
    authOrigin: "https://x.auth.eu-central-1.amazoncognito.com",
    identityPoolId: "i",
    controllerUrl: "https://u.lambda-url.eu-central-1.on.aws/",
    iotDataEndpoint: "a-ats.iot.eu-central-1.amazonaws.com",
    registryTable: "r",
    registryFields: ["mac_address"],
    presenceTable: "pr",
    guardParameter: "/g",
    claimParameter: "/c",
    alarmPrefix: "g-",
    quarantineGroup: "q",
    products: [{ id: "vaktus", fleet: "f", canary: "c", excluded: "x", shadow: "vaktus" }],
  };
  it("accepts Terraform's config and refuses a broken one", () => {
    expect(parseConfig(good).products[0]?.shadow).toBe("vaktus");
    expect(() => parseConfig({ ...good, controllerUrl: "http://x" })).toThrow(/https/);
    expect(() => parseConfig({ ...good, products: [] })).toThrow(/no products/);
    expect(() => parseConfig({ ...good, clientId: undefined })).toThrow(/clientId/);
  });
});

describe("plain words", () => {
  it("explains a record's enrolment state", () => {
    const now = 1_800_000_000_000;
    const rec = (item: Record<string, string | number | boolean>) => registryRecord(item);
    // The hand-made gateway record: enrolled, allowed=false.
    const gateway = rec({ mac_address: "28:84:85:53:14:4F", product: "gateway", allowed: false, provisioned: true });
    expect(enrolment(gateway, now).label).toBe("Enrolled");
    expect(enrolment(gateway, now).tip).toContain("allowed=false here only blocks that");
    const open = rec({ mac_address: "AA", product: "vaktus", allowed: true, provisioned: false, enrol_by: now / 1000 + 60 });
    expect(enrolment(open, now).label).toBe("Window open");
    expect(enrolment({ ...open, enrolBy: now / 1000 - 60 }, now).label).toBe("Window expired");
    expect(enrolment({ ...open, allowed: false }, now).label).toBe("Not allowed");
    expect(rec({ mac_address: "AA", product: "vaktus", last_provisioned_via: "public_key" }).via).toBe("public_key");
  });

  it("explains modes, boot reasons and relative times", () => {
    expect(mode("", "24").label).toBe("Automatic");
    expect(mode("hold", "6").tip).toContain("6 h");
    expect(mode("frozen", undefined).tone).toBe("danger");
    expect(bootReason("sw")?.tip).toContain("OTA");
    expect(bootReason("panic")?.tone).toBe("danger");
    expect(bootReason("")).toBeUndefined();
    const now = 10_000_000;
    expect(ago(now - 30_000, now)).toBe("just now");
    expect(ago(now - 5 * 60_000, now)).toBe("5 min ago");
    expect(ago(now - 3 * 3600_000, now)).toBe("3 h ago");
    expect(ago(undefined, now)).toBe("");
  });

  it("places each release against the fleet", () => {
    const rows = releaseRows(
      status({
        state: { fleet_version: "1.2.0", halted_version: "1.3.0", halted_reason: "boot loop" },
        refused_releases: [{ Version: "9.9.9", Reason: "bad signature" }],
      }),
    );
    expect(rows.map((r) => [r.version, r.key, r.badge.label])).toEqual([
      ["1.3.0", "b", "Halted"],
      ["1.2.0", "a", "On the fleet"],
      ["1.1.0", "a", "Older"],
      ["1.0.0", "a", "Older"],
      ["9.9.9", "", "Refused"],
    ]);
    expect(rows[0]?.badge.tip).toBe("boot loop");
  });
});
