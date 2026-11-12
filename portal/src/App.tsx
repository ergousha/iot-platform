import type { User, UserManager } from "oidc-client-ts";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { isCallback, role as roleOf, signOut, userManager, username } from "./auth";
import { type Clients, clients, groupThings, productStatus, scanPresence, scanRegistry } from "./aws";
import { type Config, loadConfig } from "./config";
import { presence, registryRecord } from "./data";
import { Audit } from "./screens/Audit";
import { Devices } from "./screens/Devices";
import { Enrolment } from "./screens/Enrolment";
import { Groups } from "./screens/Groups";
import { Guard } from "./screens/Guard";
import { Releases } from "./screens/Releases";
import { errorText, type Overview, Pill, type Portal, PortalContext, type Report, ReportBanner, reportOf } from "./ui";

const screens = ["Devices", "Groups", "Releases", "Enrolment", "Guard", "Audit"] as const;
type Screen = (typeof screens)[number];

const screenTips: Record<Screen, string> = {
  Devices: "Every device: online state, firmware, last restart.",
  Groups: "Canary, fleet and excluded groups; quarantine and decommission.",
  Releases: "Firmware releases per product and the OTA overrides.",
  Enrolment: "How new devices join: enrolment windows, the claim certificate, the registry.",
  Guard: "The automatic kill switch against runaway cost, and its alarms.",
  Audit: "Who signed in to the portal and what each session did.",
};

async function settle<T>(p: Promise<T>): Promise<T | Error> {
  try {
    return await p;
  } catch (e) {
    return e instanceof Error ? e : new Error(String(e));
  }
}

async function loadOverview(c: Clients): Promise<Overview> {
  const legacy = c.cfg.products.find((p) => p.legacy)?.id ?? "";
  const [statuses, pres, reg, quarantined] = await Promise.all([
    Promise.all(c.cfg.products.map(async (p) => [p.id, await settle(productStatus(c, p.id))] as const)),
    settle(scanPresence(c).then(presence)),
    settle(scanRegistry(c).then((items) => items.map((i) => registryRecord(i, legacy)))),
    settle(groupThings(c, c.cfg.quarantineGroup).then((t) => new Set(t))),
  ]);
  return { statuses: Object.fromEntries(statuses), presence: pres, registry: reg, quarantined, loadedAt: new Date() };
}

export function App() {
  const [cfg, setCfg] = useState<Config>();
  const [um, setUm] = useState<UserManager>();
  const [user, setUser] = useState<User | null>();
  const [fatal, setFatal] = useState<string>();
  const [screen, setScreen] = useState<Screen>("Devices");
  const [overview, setOverview] = useState<Overview>();
  const [report, setReport] = useState<Report>();
  const [busy, setBusy] = useState(false);
  const started = useRef(false);

  // Sign in once per page load: finish a redirect, or start one.
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    (async () => {
      const config = await loadConfig();
      const manager = userManager(config);
      setCfg(config);
      setUm(manager);
      manager.events.addUserLoaded((u) => setUser(u));
      // The session could not be renewed: sign in again (managed login's
      // cookie usually makes that a round trip without a prompt).
      manager.events.addSilentRenewError(() => void manager.signinRedirect().catch((e) => setFatal(errorText(e))));
      if (isCallback(window.location.search)) {
        const q = new URLSearchParams(window.location.search);
        if (q.has("error")) throw new Error(`sign-in failed: ${q.get("error")} ${q.get("error_description") ?? ""}`);
        const u = await manager.signinRedirectCallback();
        window.history.replaceState(null, "", "/");
        setUser(u);
        return;
      }
      const u = await manager.getUser();
      if (u && !u.expired) setUser(u);
      else await manager.signinRedirect();
    })().catch((e) => setFatal(errorText(e)));
  }, []);

  const c = useMemo(() => (cfg && user ? clients(cfg, user.id_token ?? "") : undefined), [cfg, user]);
  const role = user ? roleOf(user) : "none";

  const reload = useCallback(async () => {
    if (!c) return;
    setBusy(true);
    try {
      setOverview(await loadOverview(c));
    } finally {
      setBusy(false);
    }
  }, [c]);

  useEffect(() => {
    if (c && role !== "none" && !overview) void reload();
  }, [c, role, overview, reload]);

  const run = useCallback<Portal["run"]>(
    async (label, fn, confirm) => {
      if (confirm && !window.confirm(confirm)) return;
      setBusy(true);
      try {
        const out = await fn();
        const log = Array.isArray(out) ? out.map(String) : [];
        setReport({ label, ok: true, message: "done", log });
      } catch (e) {
        setReport(reportOf(label, e));
      } finally {
        setBusy(false);
      }
      await reload();
    },
    [reload],
  );

  if (fatal) {
    return (
      <main>
        <h1>IoT platform</h1>
        <p className="banner error">{fatal}</p>
        {um && (
          <button type="button" className="primary" onClick={() => void um.signinRedirect()}>
            Sign in again
          </button>
        )}
      </main>
    );
  }
  if (!cfg || !um || !user || !c) {
    return (
      <main>
        <p className="muted">Signing in…</p>
      </main>
    );
  }
  if (role === "none") {
    return (
      <main>
        <h1>IoT platform</h1>
        <p className="banner error">
          {username(user)} is in neither the owner nor the viewer group. Ask the owner to run{" "}
          <code>scripts/portal-user.sh role {username(user)} viewer</code>.
        </p>
        <button type="button" onClick={() => void signOut(um, cfg)}>
          Sign out
        </button>
      </main>
    );
  }

  const portal: Portal = { cfg, c, role, overview, reload, run, busy };
  return (
    <PortalContext.Provider value={portal}>
      <header className="top">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            IoT
          </span>
          IoT platform
        </div>
        <nav aria-label="Screens">
          {screens
            .filter((s) => s !== "Audit" || role === "owner")
            .map((s) => (
              <button
                type="button"
                key={s}
                className={s === screen ? "tab active" : "tab"}
                aria-current={s === screen ? "page" : undefined}
                data-tip={screenTips[s]}
                onClick={() => setScreen(s)}
              >
                {s}
              </button>
            ))}
        </nav>
        <div className="who">
          {overview && <span className="updated">Updated {overview.loadedAt.toLocaleTimeString()}</span>}
          <button
            type="button"
            disabled={busy}
            onClick={() => void reload()}
            data-tip="Reload everything from AWS. Nothing refreshes on its own."
            data-tip-align="end"
          >
            {busy ? "Loading…" : "↻ Refresh"}
          </button>
          <span className="user">
            {username(user)}
            <Pill
              tone={role === "owner" ? "info" : "neutral"}
              tip={role === "owner" ? "Owner: may change things." : "Viewer: read-only."}
            >
              {role}
            </Pill>
          </span>
          <button type="button" className="link" onClick={() => void signOut(um, cfg)}>
            Sign out
          </button>
        </div>
      </header>
      <main>
        {report && <ReportBanner report={report} onClose={() => setReport(undefined)} />}
        {screen === "Devices" && <Devices />}
        {screen === "Groups" && <Groups />}
        {screen === "Releases" && <Releases />}
        {screen === "Enrolment" && <Enrolment />}
        {screen === "Guard" && <Guard />}
        {screen === "Audit" && role === "owner" && <Audit />}
      </main>
    </PortalContext.Provider>
  );
}
