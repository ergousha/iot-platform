import { useState } from "react";
import { controller, productJobs } from "../aws";
import { type ProductConfig, productName } from "../config";
import { clip, mode, type ProductStatus, releaseRows, releaseVersion, rollbackTargets, type Tone } from "../data";
import {
  ActionButton,
  BadgePill,
  Empty,
  Failed,
  isOwner,
  Loading,
  PageIntro,
  Pill,
  Section,
  Stats,
  Th,
  Tip,
  useLoad,
  usePortal,
  when,
} from "../ui";

export function Releases() {
  const { cfg, overview } = usePortal();
  const [selected, setSelected] = useState(cfg.products[0]?.id ?? "");
  const product = cfg.products.find((p) => p.id === selected) ?? cfg.products[0];
  if (!overview || !product) return <Loading />;
  const s = overview.statuses[product.id];

  return (
    <>
      <PageIntro
        title="Releases"
        actions={
          <label className="field">
            Product
            <select value={product.id} onChange={(e) => setSelected(e.target.value)}>
              {cfg.products.map((p) => (
                <option key={p.id} value={p.id}>
                  {productName(p)}
                </option>
              ))}
            </select>
          </label>
        }
      >
        How firmware reaches the devices. Each merged release is signed and verified, goes to the canary devices first, soaks
        there, and is then promoted to the whole fleet. Owners can pause, push or undo that below.
      </PageIntro>
      {s instanceof Error || !s ? (
        <Failed error={s ?? "not loaded"} />
      ) : (
        <ProductReleases key={product.id} product={product} status={s} />
      )}
    </>
  );
}

const jobTone: Record<string, Tone> = {
  IN_PROGRESS: "info",
  SCHEDULED: "info",
  COMPLETED: "ok",
  CANCELED: "neutral",
  DELETION_IN_PROGRESS: "neutral",
};

function ProductReleases({ product, status }: { product: ProductConfig; status: ProductStatus }) {
  const portal = usePortal();
  const { c } = portal;
  const [version, setVersion] = useState("");
  const [jobs, jobsError, jobsLoading, loadJobs] = useLoad<Awaited<ReturnType<typeof productJobs>>>();
  const st = status.state;
  const m = mode(st.ota_mode, st.soak_hours);
  const currentMode = st.ota_mode || "auto";
  const verified = (status.verified_releases ?? []).map(releaseVersion);
  const targets = rollbackTargets(status);
  const rows = releaseRows(status);
  const name = productName(product);
  const override = (action: string, v?: string) => async () =>
    (await controller(c, { action, product: product.id, ...(v ? { version: v } : {}) })).log ?? [];

  return (
    <>
      {product.description && <p className="callout">{product.description}</p>}
      <Stats
        items={[
          { label: "OTA mode", value: <Pill tone={m.tone}>{m.label}</Pill>, tip: m.tip },
          {
            label: "Fleet version",
            value: <span className="mono">{st.fleet_version || "none yet"}</span>,
            tone: "info",
            tip: "The version every device of the product is meant to run.",
          },
          {
            label: "Soak time",
            value: `${st.soak_hours || "?"} h`,
            tip: "How long a release must run on the canaries without trouble before it is promoted.",
          },
          {
            label: "Halted",
            value: st.halted_version ? <span className="mono">{st.halted_version}</span> : "none",
            tone: st.halted_version ? "danger" : "ok",
            tip: st.halted_version
              ? `Stopped on the canaries: ${clip(st.halted_reason, 200)}`
              : "No release is stopped. A release that fails on the canaries is halted and never reaches the fleet.",
          },
        ]}
      />

      <div className="grid">
        <Section
          title="Releases"
          tip="Releases the controller has seen for this product, newest first. Hover a status for details."
        >
          {rows.length === 0 ? (
            <Empty>No releases yet.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <Th>Version</Th>
                  <Th tip="The key that signed the release; devices accept only keys they know.">Signing key</Th>
                  <Th align="end">Status</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={`${r.badge.label}/${r.version}`}>
                    <td className="mono cell-main">{r.version}</td>
                    <td className="mono small muted">{r.key}</td>
                    <td>
                      <BadgePill badge={r.badge} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <h3>
            Active jobs <Tip text="OTA jobs AWS IoT is running for this product right now." />
          </h3>
          {(status.active_jobs ?? []).length === 0 ? (
            <p className="muted">None.</p>
          ) : (
            <div className="pills">
              {(status.active_jobs ?? []).map((j) => (
                <Pill key={j} tone="info">
                  <span className="mono">{j}</span>
                </Pill>
              ))}
            </div>
          )}
        </Section>

        {isOwner(portal) && (
          <Section title="Overrides" tip="Manual control over the automatic rollout. Every change is emailed.">
            <h3>Mode</h3>
            <fieldset className="seg" aria-label="OTA mode">
              {(
                [
                  ["auto", "Automatic", "resume"],
                  ["hold", "Hold", "hold"],
                  ["frozen", "Freeze", "freeze"],
                ] as const
              ).map(([value, label, action]) =>
                value === currentMode ? (
                  <span key={value} className="current" data-tip={mode(value, st.soak_hours).tip}>
                    {label}
                  </span>
                ) : (
                  <ActionButton
                    key={value}
                    label={label}
                    tip={mode(value, st.soak_hours).tip}
                    confirm={`Switch ${name} to ${label.toLowerCase()}?`}
                    run={override(action)}
                  />
                ),
              )}
            </fieldset>

            <h3>Push a release</h3>
            <div className="btn-row">
              <select value={version} onChange={(e) => setVersion(e.target.value)} aria-label="version">
                <option value="">Newest verified</option>
                {verified.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
              <ActionButton
                label="Promote to fleet"
                primary
                tip="Send this release to the whole fleet now, skipping the soak time."
                confirm={`Promote ${version || "the newest verified release"} of ${name} to the fleet now, skipping the soak gate?`}
                run={override("promote", version)}
              />
              <ActionButton
                label="Rerun canary"
                tip="Run the canary stage again for this release (clears its halt)."
                confirm={`Rerun the canary for ${version || "the newest verified release"} of ${name}?`}
                run={override("rerun", version)}
              />
            </div>

            <h3>Roll back</h3>
            {targets.length === 0 ? (
              <p className="muted small">No verified version below the fleet's to roll back to.</p>
            ) : (
              <div className="btn-row">
                {targets.slice(0, 5).map((v) => (
                  <ActionButton
                    key={v}
                    label={`Roll back to ${v}`}
                    danger
                    tip={`Downgrade every device to ${v}. The current version is halted and the product goes on hold.`}
                    confirm={`Downgrade the whole ${name} fleet to ${v}? ${st.fleet_version} is halted and the product goes on hold.`}
                    run={override("rollback", v)}
                  />
                ))}
              </div>
            )}
          </Section>
        )}
      </div>

      <Section
        title="Job history"
        tip="The product's OTA jobs in AWS IoT, newest first. Loaded on demand."
        actions={
          <button type="button" disabled={jobsLoading} onClick={() => void loadJobs(() => productJobs(c, product.id))}>
            {jobsLoading ? "Loading…" : jobs ? "↻ Reload jobs" : "Load jobs"}
          </button>
        }
      >
        {jobsError !== undefined && <Failed error={jobsError} />}
        {jobs &&
          (jobs.length === 0 ? (
            <Empty>No OTA jobs yet.</Empty>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <Th>Job</Th>
                    <Th>Status</Th>
                    <Th tip="SNAPSHOT: a fixed list of devices. CONTINUOUS: also devices that join the group later.">Target</Th>
                    <Th align="end">Created</Th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map((j) => (
                    <tr key={j.jobId}>
                      <td className="mono small">{j.jobId}</td>
                      <td>
                        <Pill tone={jobTone[j.status ?? ""] ?? "neutral"}>
                          {(j.status ?? "").toLowerCase().replace(/_/g, " ")}
                        </Pill>
                      </td>
                      <td className="small">{j.targetSelection?.toLowerCase()}</td>
                      <td className="small muted nowrap">{when(j.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
      </Section>
    </>
  );
}
