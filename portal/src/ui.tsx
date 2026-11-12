import { createContext, type ReactNode, useCallback, useContext, useState } from "react";
import type { Role } from "./auth";
import type { Clients } from "./aws";
import { ControllerError } from "./aws";
import type { Config } from "./config";
import { type Badge, clip, type Presence, type ProductStatus, type RegistryRecord, type Tone } from "./data";

/** Everything the screens share, loaded at sign-in and on Refresh only. */
export interface Overview {
  statuses: Record<string, ProductStatus | Error>;
  presence: Map<string, Presence> | Error;
  registry: RegistryRecord[] | Error;
  quarantined: Set<string> | Error;
  loadedAt: Date;
}

export interface Portal {
  cfg: Config;
  c: Clients;
  role: Role;
  overview: Overview | undefined;
  reload: () => Promise<void>;
  /**
   * run performs an owner action, reports it, and reloads the overview. fn
   * may resolve to log lines; anything else reports no log.
   */
  run: (label: string, fn: () => Promise<unknown>, confirm?: string) => Promise<void>;
  busy: boolean;
}

export const PortalContext = createContext<Portal | undefined>(undefined);

export function usePortal(): Portal {
  const p = useContext(PortalContext);
  if (!p) throw new Error("no portal context");
  return p;
}

export function isOwner(p: Portal): boolean {
  return p.role === "owner";
}

export interface Report {
  label: string;
  ok: boolean;
  message: string;
  log: string[];
}

export function errorText(e: unknown): string {
  if (e instanceof Error) return clip(e.message, 500);
  return clip(String(e), 500);
}

export function reportOf(label: string, e: unknown): Report {
  return { label, ok: false, message: errorText(e), log: e instanceof ControllerError ? e.log : [] };
}

export function ReportBanner({ report, onClose }: { report: Report; onClose: () => void }) {
  return (
    <div className={report.ok ? "banner ok" : "banner error"} role="status">
      <div className="banner-head">
        <strong>
          {report.ok ? "✓" : "✕"} {report.label}
        </strong>
        <span>{report.message}</span>
        <button type="button" className="link" onClick={onClose}>
          Dismiss
        </button>
      </div>
      {report.log.length > 0 && (
        <ul className="log">
          {report.log.slice(0, 30).map((l, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: a static list, replaced whole and never reordered
            <li key={i}>{clip(l, 300)}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function Failed({ error }: { error: unknown }) {
  return <p className="banner error">{errorText(error)}</p>;
}

/**
 * Button for an owner action; hidden for viewers. tip is its tooltip,
 * confirm a question asked before it runs.
 */
export function ActionButton(props: {
  label: string;
  tip?: string;
  danger?: boolean;
  primary?: boolean;
  confirm?: string;
  disabled?: boolean;
  className?: string;
  run: () => Promise<unknown>;
}) {
  const p = usePortal();
  if (!isOwner(p)) return null;
  const classes = [props.className, props.danger && "danger", props.primary && "primary"].filter(Boolean).join(" ");
  return (
    <button
      type="button"
      className={classes || undefined}
      data-tip={props.tip}
      aria-description={props.tip}
      disabled={p.busy || props.disabled}
      onClick={() => void p.run(props.label, props.run, props.confirm)}
    >
      {props.label}
    </button>
  );
}

/** A card: a titled block of a page. */
export function Section({
  title,
  tip,
  intro,
  actions,
  children,
}: {
  title: ReactNode;
  tip?: string;
  intro?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <section className="card">
      <header className="card-head">
        <h2>
          {title}
          {tip && <Tip text={tip} />}
        </h2>
        {actions && <div className="btn-row">{actions}</div>}
      </header>
      {intro && <p className="card-intro">{intro}</p>}
      {children}
    </section>
  );
}

/** The top of a screen: its name and what it is for, in a sentence or two. */
export function PageIntro({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-intro">
      <div>
        <h1>{title}</h1>
        <p className="lead">{children}</p>
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

/** An ⓘ that explains on hover or focus. */
export function Tip({ text, align }: { text: string; align?: "start" | "end" }) {
  return (
    <button type="button" className="tip-icon" data-tip={text} data-tip-align={align} aria-label={text}>
      i
    </button>
  );
}

/** A coloured status label; tip explains it. */
export function Pill({ tone = "neutral", tip, children }: { tone?: Tone; tip?: string; children: ReactNode }) {
  return (
    <span className={`pill ${tone}`} data-tip={tip} tabIndex={tip ? 0 : undefined}>
      {children}
    </span>
  );
}

export function BadgePill({ badge }: { badge: Badge | undefined }) {
  return badge ? (
    <Pill tone={badge.tone} tip={badge.tip}>
      {badge.label}
    </Pill>
  ) : null;
}

/** A green or red light. */
export function Light({ on, label }: { on: boolean; label?: string }) {
  return (
    <span className="light-label">
      <span className={on ? "light on" : "light off"} aria-hidden="true" />
      {label ?? (on ? "Online" : "Offline")}
    </span>
  );
}

export interface StatItem {
  label: string;
  value: ReactNode;
  tone?: Tone;
  tip?: string;
}

/** A row of headline numbers. */
export function Stats({ items }: { items: StatItem[] }) {
  return (
    <div className="stats">
      {items.map((s) => (
        <div key={s.label} className={`stat ${s.tone ?? ""}`}>
          <div className="stat-label">
            {s.label}
            {s.tip && <Tip text={s.tip} />}
          </div>
          <div className="stat-value">{s.value}</div>
        </div>
      ))}
    </div>
  );
}

/** Label / value rows: KeyValues holding KV children. */
export function KeyValues({ children }: { children: ReactNode }) {
  return <dl className="kv">{children}</dl>;
}

export function KV({ label, tip, children }: { label: ReactNode; tip?: string; children: ReactNode }) {
  return (
    <div className="kv-row">
      <dt>
        {label}
        {tip && <Tip text={tip} />}
      </dt>
      <dd>{children}</dd>
    </div>
  );
}

/** A table header cell with an optional explanation. */
export function Th({ children, tip, align }: { children?: ReactNode; tip?: string; align?: "start" | "end" }) {
  return (
    <th>
      {children}
      {tip && <Tip text={tip} align={align} />}
    </th>
  );
}

/** JSON written by devices, shown as size-limited text. */
export function JsonText({ value, max = 8000 }: { value: unknown; max?: number }) {
  return <pre className="json">{clip(JSON.stringify(value, null, 2), max)}</pre>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function when(t: number | Date | string | undefined): string {
  if (t === undefined || t === "") return "";
  const d = t instanceof Date ? t : new Date(t);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function Loading() {
  return <p className="muted loading">Loading…</p>;
}

/** useLoad runs a loader on demand (never on a timer). */
export function useLoad<T>(): [T | undefined, unknown, boolean, (fn: () => Promise<T>) => Promise<void>] {
  const [value, setValue] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(false);
  // Stable across renders, so effects can list it as a dependency.
  const load = useCallback(async (fn: () => Promise<T>) => {
    setLoading(true);
    setError(undefined);
    try {
      setValue(await fn());
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, []);
  return [value, error, loading, load];
}
