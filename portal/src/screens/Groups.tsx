import { controller, moveThing } from "../aws";
import { productName } from "../config";
import { move, type Placement, placement } from "../data";
import { ActionButton, Empty, Failed, isOwner, Loading, PageIntro, Pill, Section, Th, usePortal } from "../ui";
import { groupTips, ProductErrors, useRows } from "./Devices";

const placements: [Placement, string][] = [
  ["canary", "Canary"],
  ["fleet", "Fleet"],
  ["excluded", "Excluded"],
];

// Membership: canary and excluded toggles go straight to AWS IoT (the owner
// role may move a thing within its product's groups); quarantine, target and
// decommission go through the OTA controller.
export function Groups() {
  const portal = usePortal();
  const { c, overview } = portal;
  const { rows, errors } = useRows();
  if (!overview) return <Loading />;
  const quarantined = overview.quarantined instanceof Error ? undefined : overview.quarantined;
  const owner = isOwner(portal);

  return (
    <>
      <PageIntro title="Groups">
        Where each device sits in its product's rollout, and the per-device safety switches. Moves take effect for the next OTA
        job; quarantine takes effect immediately.
      </PageIntro>
      <ProductErrors errors={errors} />
      <div className="legend">
        <div>
          <Pill tone="warn">Canary</Pill>
          <p>Gets each new release first. If it misbehaves there, the release is halted before it reaches anyone else.</p>
        </div>
        <div>
          <Pill>Fleet</Pill>
          <p>The rest of the devices. They get a release once it has soaked on the canaries.</p>
        </div>
        <div>
          <Pill tone="danger">Excluded</Pill>
          <p>Gets no fleet job: usually a device that failed one. Target gives it a job of its own.</p>
        </div>
        <div>
          <Pill tone="danger">Quarantined</Pill>
          <p>AWS IoT refuses the device entirely: it cannot connect or publish until released.</p>
        </div>
      </div>
      <Section title="Devices by group">
        {rows.length === 0 ? (
          <Empty>No devices yet.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <Th>Device</Th>
                  <Th>Product</Th>
                  <Th tip="The device's group in its product's rollout. Owners click another option to move it.">
                    Rollout group
                  </Th>
                  <Th tip="Quarantine cuts one device off AWS IoT; Release lets it connect again.">Quarantine</Th>
                  {owner && (
                    <Th
                      tip="Target: a job of its own for the fleet version. Decommission: remove the device for good."
                      align="end"
                    >
                      Actions
                    </Th>
                  )}
                </tr>
              </thead>
              <tbody>
                {rows.map(({ product, status, thing }) => {
                  const at = placement(status, thing);
                  const isQuarantined = quarantined?.has(thing) ?? false;
                  const call =
                    (action: string, extra: Record<string, string> = {}) =>
                    async () =>
                      (await controller(c, { action, product: product.id, thing, ...extra })).log ?? [];
                  return (
                    <tr key={`${product.id}/${thing}`}>
                      <td className="mono cell-main">{thing}</td>
                      <td>{productName(product)}</td>
                      <td>
                        <fieldset className="seg" aria-label={`Rollout group of ${thing}`}>
                          {placements.map(([dest, label]) =>
                            dest === at ? (
                              <span key={dest} className="current" data-tip={groupTips[dest]}>
                                {label}
                              </span>
                            ) : (
                              <ActionButton
                                key={dest}
                                label={label}
                                tip={`Move to ${label.toLowerCase()}. ${groupTips[dest]}`}
                                confirm={`Move ${thing} from ${at} to ${dest}?`}
                                run={async () => {
                                  const m = move(product, at, dest);
                                  await moveThing(c, thing, m.add, m.remove);
                                  return [`${thing}: ${at} -> ${dest}`];
                                }}
                              />
                            ),
                          )}
                        </fieldset>
                      </td>
                      <td>
                        <div className="btn-row">
                          {quarantined === undefined ? (
                            <Pill>unknown</Pill>
                          ) : isQuarantined ? (
                            <Pill tone="danger">Quarantined</Pill>
                          ) : (
                            <Pill tone="ok">Allowed</Pill>
                          )}
                          {isQuarantined ? (
                            <ActionButton
                              label="Release"
                              tip="Let the device connect again."
                              confirm={`Let ${thing} connect again?`}
                              run={call("unquarantine")}
                            />
                          ) : (
                            <ActionButton
                              label="Quarantine"
                              danger
                              tip="Cut this device off AWS IoT now: its next connect or publish is refused."
                              confirm={`Quarantine ${thing}? AWS IoT refuses its next publish or connect.`}
                              run={call("quarantine")}
                            />
                          )}
                        </div>
                      </td>
                      {owner && (
                        <td>
                          <div className="btn-row">
                            <ActionButton
                              label="Target"
                              tip="Give this device its own OTA job for the fleet version (also brings it back from excluded)."
                              confirm={`Give ${thing} its own job for the fleet version?`}
                              run={call("target")}
                            />
                            <ActionButton
                              label="Decommission"
                              danger
                              tip="Remove the device for good: its certificates go inactive and the thing is deleted."
                              run={async () => {
                                const typed = window.prompt(
                                  `Decommission ${thing}: its certificates go INACTIVE and the thing is deleted. ` +
                                    "Re-enrolment needs the bench (ergo commission --reprovision). Type the thing name to confirm.",
                                );
                                if (typed === null) return ["cancelled"];
                                return call("decommission", { confirm: typed.trim() })();
                              }}
                            />
                          </div>
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {!portal.busy && overview.quarantined instanceof Error && <Failed error={overview.quarantined} />}
      </Section>
    </>
  );
}
