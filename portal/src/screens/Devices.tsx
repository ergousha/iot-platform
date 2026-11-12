import { useCallback, useEffect, useState } from "react";
import { executions, setDesired, shadow } from "../aws";
import { type ProductConfig, productName } from "../config";
import { ago, bootReason, clip, type ProductStatus, placement, type Tone } from "../data";
import {
  ActionButton,
  BadgePill,
  Empty,
  Failed,
  isOwner,
  JsonText,
  Light,
  Loading,
  PageIntro,
  Pill,
  Section,
  Stats,
  Th,
  useLoad,
  usePortal,
  when,
} from "../ui";

export interface Row {
  product: ProductConfig;
  status: ProductStatus;
  thing: string;
}

/** rows lists every device of every product the controller reported. */
export function useRows(): { rows: Row[]; errors: [string, Error][] } {
  const { cfg, overview } = usePortal();
  const rows: Row[] = [];
  const errors: [string, Error][] = [];
  for (const product of cfg.products) {
    const status = overview?.statuses[product.id];
    if (status instanceof Error) {
      errors.push([productName(product), status]);
      continue;
    }
    if (!status) continue;
    const things = new Set([...Object.keys(status.devices ?? {}), ...(status.excluded ?? [])]);
    for (const thing of [...things].sort()) rows.push({ product, status, thing });
  }
  return { rows, errors };
}

export const groupTone: Record<string, Tone> = { canary: "warn", fleet: "neutral", excluded: "danger" };

export const groupTips: Record<string, string> = {
  canary: "Canary: gets each new release first, before the rest of the fleet.",
  fleet: "Fleet: gets a release once it has soaked on the canaries.",
  excluded: "Excluded: gets no fleet job (usually a device that failed one).",
};

export function ProductErrors({ errors }: { errors: [string, Error][] }) {
  return (
    <>
      {errors.map(([name, e]) => (
        <p key={name} className="banner error">
          {name}: {e.message}
        </p>
      ))}
    </>
  );
}

export function Devices() {
  const { overview } = usePortal();
  const { rows, errors } = useRows();
  const [selected, setSelected] = useState<Row>();
  if (!overview) return <Loading />;
  const pres = overview.presence instanceof Error ? undefined : overview.presence;
  const quarantined = overview.quarantined instanceof Error ? undefined : overview.quarantined;
  const now = overview.loadedAt.getTime();
  const online = (r: Row) => pres?.get(r.thing)?.online ?? r.status.devices[r.thing]?.online ?? false;
  const onlineCount = rows.filter(online).length;
  const quarantinedCount = rows.filter((r) => quarantined?.has(r.thing)).length;

  return (
    <>
      <PageIntro title="Devices">
        Every device the OTA controller tracks, across all products. Select a row to see the device's shadow, its recent OTA jobs
        and its registry record.
      </PageIntro>
      <ProductErrors errors={errors} />
      {overview.presence instanceof Error && <Failed error={overview.presence} />}
      <Stats
        items={[
          { label: "Devices", value: rows.length },
          { label: "Online", value: onlineCount, tone: "ok", tip: "Connected to AWS IoT right now." },
          {
            label: "Offline",
            value: rows.length - onlineCount,
            tone: rows.length - onlineCount > 0 ? "danger" : undefined,
            tip: "Not connected: powered off, no network, or refused.",
          },
          {
            label: "Quarantined",
            value: quarantinedCount,
            tone: quarantinedCount > 0 ? "danger" : undefined,
            tip: "AWS IoT refuses these devices entirely. See Groups.",
          },
        ]}
      />
      <Section title="All devices">
        {rows.length === 0 ? (
          <Empty>No devices yet. A device appears here after it enrols and reports to its shadow.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <Th tip="Online: connected to AWS IoT now, from its connect and disconnect events.">Status</Th>
                  <Th tip="The device's thing name: its MAC address without separators.">Device</Th>
                  <Th>Product</Th>
                  <Th tip="The firmware version the device reports.">Firmware</Th>
                  <Th tip="When it last connected (online) or disconnected (offline). Hover for the exact times.">Last seen</Th>
                  <Th tip="Why the device last restarted, as the ESP32 reports it. Hover a value for its meaning.">
                    Last restart
                  </Th>
                  <Th tip="Where the device sits in its product's rollout. Change it on the Groups screen." align="end">
                    Group
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const d = r.status.devices[r.thing];
                  const p = pres?.get(r.thing);
                  const isOnline = online(r);
                  const isSelected = selected?.thing === r.thing && selected.product.id === r.product.id;
                  const at = placement(r.status, r.thing);
                  const seen = isOnline ? p?.lastConnected : (p?.lastDisconnected ?? p?.lastConnected);
                  const exact = `Connected: ${when(p?.lastConnected) || "never"}. Disconnected: ${when(p?.lastDisconnected) || "never"}.`;
                  return (
                    <tr
                      key={`${r.product.id}/${r.thing}`}
                      className={isSelected ? "clickable selected" : "clickable"}
                      onClick={() => setSelected(r)}
                      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSelected(r)}
                      tabIndex={0}
                      aria-selected={isSelected}
                    >
                      <td>
                        <Light on={isOnline} />
                      </td>
                      <td className="mono cell-main">{r.thing}</td>
                      <td>{productName(r.product)}</td>
                      <td>{d?.fw ? <Pill tone="info">{clip(d.fw, 24)}</Pill> : <span className="muted">unknown</span>}</td>
                      <td className="nowrap">
                        <span data-tip={exact}>
                          {seen === undefined ? (
                            <span className="muted">never</span>
                          ) : (
                            <>
                              {isOnline ? "connected " : "disconnected "}
                              {ago(seen, now)}
                            </>
                          )}
                        </span>
                      </td>
                      <td>
                        <BadgePill badge={bootReason(d?.boot_reason)} />
                      </td>
                      <td>
                        <span className="pills">
                          <Pill tone={groupTone[at]} tip={groupTips[at]}>
                            {at}
                          </Pill>
                          {quarantined?.has(r.thing) && (
                            <Pill tone="danger" tip="AWS IoT refuses this device entirely.">
                              quarantined
                            </Pill>
                          )}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      {selected && <DeviceDetail key={`${selected.product.id}/${selected.thing}`} row={selected} />}
    </>
  );
}

const MAX_DESIRED_BYTES = 8 * 1024; // an AWS IoT shadow document's limit

const executionTone: Record<string, Tone> = {
  SUCCEEDED: "ok",
  FAILED: "danger",
  TIMED_OUT: "danger",
  REJECTED: "danger",
  QUEUED: "info",
  IN_PROGRESS: "info",
  CANCELED: "neutral",
  REMOVED: "neutral",
};

function DeviceDetail({ row }: { row: Row }) {
  const portal = usePortal();
  const { c, overview } = portal;
  const [detail, error, loading, load] = useLoad<{ shadow: unknown; executions: Awaited<ReturnType<typeof executions>> }>();
  const [draft, setDraft] = useState("{\n  \n}");
  const [draftError, setDraftError] = useState<string>();
  const registry =
    overview && !(overview.registry instanceof Error) ? overview.registry.find((r) => r.thing === row.thing) : undefined;

  const { thing } = row;
  const shadowName = row.product.shadow;
  const fetchDetail = useCallback(
    () =>
      load(async () => {
        const [s, e] = await Promise.all([shadow(c, thing, shadowName), executions(c, thing)]);
        return { shadow: s, executions: e };
      }),
    [c, thing, shadowName, load],
  );
  // Once per selected device (the component is keyed by it).
  useEffect(() => void fetchDetail(), [fetchDetail]);

  const parsed = (): Record<string, unknown> | undefined => {
    try {
      const v: unknown = JSON.parse(draft);
      if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("desired state must be a JSON object");
      if (new TextEncoder().encode(draft).length > MAX_DESIRED_BYTES) throw new Error("over 8 KB");
      setDraftError(undefined);
      return v as Record<string, unknown>;
    } catch (e) {
      setDraftError(e instanceof Error ? e.message : String(e));
      return undefined;
    }
  };

  return (
    <Section
      title={
        <>
          <span className="mono">{row.thing}</span>
          <span className="muted">· {productName(row.product)}</span>
        </>
      }
      actions={
        <button type="button" disabled={loading} onClick={() => void fetchDetail()}>
          ↻ Reload device
        </button>
      }
    >
      {loading && <Loading />}
      {error !== undefined && <Failed error={error} />}
      <div className="grid">
        <div>
          <h3>Shadow “{row.product.shadow}”</h3>
          <p className="card-intro">
            The device's settings in AWS IoT: <em>desired</em> is what you asked for, <em>reported</em> what the device applied.
          </p>
          {detail && (detail.shadow === undefined ? <Empty>No shadow yet.</Empty> : <JsonText value={detail.shadow} />)}
          {isOwner(portal) && (
            <>
              <h3>Set desired state</h3>
              <p className="card-intro">
                A JSON object merged into <em>desired</em>; the device applies it the next time it reads its shadow.
              </p>
              <textarea value={draft} onChange={(e) => setDraft(e.target.value)} rows={6} spellCheck={false} />
              {draftError && <p className="banner error">{draftError}</p>}
              <div className="btn-row">
                <ActionButton
                  label="Update desired"
                  primary
                  tip="Merge this JSON into the shadow's desired state."
                  confirm={`Set desired state on ${row.thing}'s ${row.product.shadow} shadow?`}
                  run={async () => {
                    const desired = parsed();
                    if (!desired) throw new Error(draftError ?? "invalid JSON");
                    await setDesired(c, row.product, row.thing, desired);
                    await fetchDetail();
                    return ["desired state merged into the shadow; the device applies it on its next delta"];
                  }}
                />
              </div>
            </>
          )}
        </div>
        <div>
          <h3>OTA jobs</h3>
          {detail &&
            (detail.executions.length === 0 ? (
              <Empty>No OTA jobs for this device.</Empty>
            ) : (
              <table>
                <tbody>
                  {detail.executions.map((x) => {
                    const st = x.jobExecutionSummary?.status ?? "";
                    return (
                      <tr key={x.jobId}>
                        <td className="mono small">{x.jobId}</td>
                        <td>
                          <Pill tone={executionTone[st] ?? "neutral"}>{st.toLowerCase().replace("_", " ")}</Pill>
                        </td>
                        <td className="small muted nowrap">{when(x.jobExecutionSummary?.lastUpdatedAt)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ))}
          <h3>Registry record</h3>
          {registry ? <JsonText value={registry.raw} /> : <Empty>No registry record.</Empty>}
          <h3>Reported to the controller</h3>
          <JsonText value={row.status.devices[row.thing] ?? {}} />
        </div>
      </div>
    </Section>
  );
}
