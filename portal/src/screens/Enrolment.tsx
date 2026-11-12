import { useEffect } from "react";
import { jsonParameter } from "../aws";
import { productById, productName } from "../config";
import { ago, enrolMethods, enrolment, windowState } from "../data";
import {
  BadgePill,
  Empty,
  Failed,
  JsonText,
  KeyValues,
  KV,
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

// Read-only: arming a window is `ergo commission` at the bench.
export function Enrolment() {
  const { c, cfg, overview } = usePortal();
  const [claim, claimError, , loadClaim] = useLoad<Record<string, unknown> | undefined>();
  useEffect(() => void loadClaim(() => jsonParameter(c, cfg.claimParameter)), [c, cfg.claimParameter, loadClaim]); // once per session
  if (!overview) return <Loading />;
  if (overview.registry instanceof Error) return <Failed error={overview.registry} />;

  const now = overview.loadedAt.getTime();
  const registry = overview.registry;
  const pending = registry
    .map((r) => ({ r, w: windowState(r, now) }))
    .filter(({ w }) => w !== "none")
    .sort((a, b) => (b.r.enrolBy ?? Number.MAX_SAFE_INTEGER) - (a.r.enrolBy ?? Number.MAX_SAFE_INTEGER));
  const open = pending.filter(({ w }) => w === "open").length;
  const enrolled = registry.filter((r) => r.provisioned).length;
  const legacyName = productName(cfg.products.find((p) => p.legacy));

  const rotatedAt = typeof claim?.rotated_at === "string" ? claim.rotated_at : undefined;
  const rotatePending = claim?.rotate_pending === true;
  const otherClaimFields = claim
    ? Object.fromEntries(Object.entries(claim).filter(([k]) => k !== "rotated_at" && k !== "rotate_pending"))
    : {};

  return (
    <>
      <PageIntro title="Enrolment">
        How a new device joins. At the bench, <code>ergo commission</code> registers the device's MAC address and public key and
        opens an enrolment window. The device then uses the shared <em>claim certificate</em> to ask AWS IoT for its own
        certificate, once. Nothing can be enrolled from this page.
      </PageIntro>
      <Stats
        items={[
          { label: "Registered", value: registry.length, tip: "Devices with a registry record." },
          { label: "Enrolled", value: enrolled, tone: "ok", tip: "Records whose device has its own certificate." },
          {
            label: "Open windows",
            value: open,
            tone: open > 0 ? "warn" : undefined,
            tip: "Records that may enrol right now. While one is open, the claim certificate is active.",
          },
        ]}
      />

      <div className="grid">
        <Section
          title="Claim certificate"
          tip="The certificate a new device enrols with. It is shared by every new device, so it is kept inactive except during enrolment windows, and rotated afterwards."
        >
          {claimError !== undefined && <Failed error={claimError} />}
          <KeyValues>
            <KV
              label="Status"
              tip="Worked out from the windows on this page: the OTA controller turns the claim on only while an enrolment window is open and the guard is clear, at its next run."
            >
              {open > 0 ? <Pill tone="warn">Active: a window is open</Pill> : <Pill tone="ok">Inactive: no window open</Pill>}
            </KV>
            <KV
              label="Last rotated"
              tip="A new claim certificate replaces the old one after each enrolment window, so a copy taken from a device is useless."
            >
              {rotatedAt ? (
                <>
                  {ago(Date.parse(rotatedAt), now)} <span className="muted small">({when(rotatedAt)})</span>
                </>
              ) : (
                <span className="muted">never</span>
              )}
            </KV>
            <KV label="Rotation pending" tip="Yes: the controller replaces the claim at its next run.">
              {rotatePending ? <Pill tone="warn">Yes</Pill> : <Pill>No</Pill>}
            </KV>
          </KeyValues>
          {Object.keys(otherClaimFields).length > 0 && (
            <details>
              <summary>Other fields</summary>
              <JsonText value={otherClaimFields} />
            </details>
          )}
        </Section>

        <Section
          title="Enrolment windows"
          tip="Records allowed to enrol and not yet enrolled. A window with no end date never expires."
        >
          {pending.length === 0 ? (
            <Empty>
              No open windows. Run <code>ergo commission</code> at the bench to open one.
            </Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <Th>MAC</Th>
                  <Th>Product</Th>
                  <Th>Window</Th>
                  <Th align="end">Enrol by</Th>
                </tr>
              </thead>
              <tbody>
                {pending.map(({ r, w }) => (
                  <tr key={r.mac}>
                    <td className="mono">{r.mac}</td>
                    <td>{productName(productById(cfg, r.product), r.product)}</td>
                    <td>{w === "open" ? <Pill tone="warn">open</Pill> : <Pill>expired</Pill>}</td>
                    <td className="small nowrap">{r.enrolBy === undefined ? "no limit" : when(r.enrolBy * 1000)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
      </div>

      <Section
        title="Registry"
        intro={
          <>
            One record per device, written by <code>ergo commission</code>. A record enrols its device once: after that the device
            keeps its own certificate, and enrolling it again always starts at the bench.
          </>
        }
      >
        {registry.length === 0 ? (
          <Empty>No records.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <Th>MAC</Th>
                  <Th>Product</Th>
                  <Th tip="Enrolled: the device has its own certificate. Window open: it may enrol now. Hover a status for details.">
                    Status
                  </Th>
                  <Th tip="How the device proved itself when it enrolled: the key in its secure element, or the product's shared secret.">
                    Enrolled with
                  </Th>
                  <Th align="end">Enrolled</Th>
                </tr>
              </thead>
              <tbody>
                {registry.map((r) => (
                  <tr key={r.mac}>
                    <td className="mono cell-main">{r.mac}</td>
                    <td>
                      <div className="pills">
                        {productName(productById(cfg, r.product), r.product)}
                        {r.legacy && (
                          <Pill
                            tip={
                              `Written before the platform had products: it has no product attribute, so it belongs to ${legacyName}, ` +
                              "and no enrolment history." +
                              (r.allowed
                                ? ""
                                : " Its allowed=false only blocks a new enrolment; the enrolled device is unaffected.") +
                              " ergo commission rewrites the record when the device is enrolled again."
                            }
                          >
                            legacy record
                          </Pill>
                        )}
                      </div>
                    </td>
                    <td>
                      <BadgePill badge={enrolment(r, now)} />
                    </td>
                    <td>{r.via ? (enrolMethods[r.via] ?? r.via) : <span className="muted">not recorded</span>}</td>
                    <td className="small nowrap">
                      {r.enrolledAt ? when(r.enrolledAt) : <span className="muted">not recorded</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </>
  );
}
