import { useCallback, useEffect } from "react";
import { controller, guardAlarms, jsonParameter } from "../aws";
import { ago, clip, type Tone } from "../data";
import { ActionButton, Empty, Failed, JsonText, Loading, PageIntro, Pill, Section, Th, useLoad, usePortal, when } from "../ui";

// The kill switch's stages, each including the ones before it (guard.tf).
const stages = [
  {
    scope: "provisioning",
    title: "Provisioning",
    text: "The claim certificate goes inactive: no new device can enrol.",
  },
  {
    scope: "traffic",
    title: "Traffic",
    text: "Also disables the IoT rules that cost money per message (telemetry logging).",
  },
  {
    scope: "fleet",
    title: "Fleet",
    text: "Also attaches a deny-all policy to every fleet group: all devices go offline.",
  },
];

// What each guard alarm watches, by its name without the guard prefix.
const alarmInfo: Record<string, [string, string]> = {
  "publish-5m": ["Messages published, 5 minutes", "traffic"],
  "publish-30m": ["Messages published, 30 minutes", "fleet"],
  "connect-5m": ["Connection attempts, 5 minutes", "provisioning"],
  "hook-5m": ["Enrolment requests, 5 minutes", "provisioning"],
  "ota-errors": ["OTA controller errors", "email only"],
  "kill-switch-errors": ["Kill switch errors", "email only"],
};

const alarmTone: Record<string, Tone> = { OK: "ok", ALARM: "danger", INSUFFICIENT_DATA: "neutral" };
const alarmLabel: Record<string, string> = { OK: "OK", ALARM: "Alarm", INSUFFICIENT_DATA: "No data" };

// The kill switch's state and the alarms that feed it. Device
// Defender is unavailable, so "blame" is the trip reasons and the alarms'
// own state reasons: fleet-wide, not per device.
export function Guard() {
  const portal = usePortal();
  const { c, cfg, overview } = portal;
  const [data, error, loading, load] = useLoad<{
    state: Record<string, unknown> | undefined;
    alarms: Awaited<ReturnType<typeof guardAlarms>>;
  }>();
  const refresh = useCallback(
    () =>
      load(async () => {
        const [state, alarms] = await Promise.all([jsonParameter(c, cfg.guardParameter), guardAlarms(c)]);
        return { state, alarms };
      }),
    [c, cfg.guardParameter, load],
  );
  // Follows the overview: loads with it and again on every Refresh.
  const loadedAt = overview?.loadedAt;
  useEffect(() => {
    if (loadedAt) void refresh();
  }, [refresh, loadedAt]);

  const now = loadedAt?.getTime() ?? 0;
  const tripped = data?.state?.tripped === true;
  const scope = typeof data?.state?.scope === "string" ? data.state.scope : "";
  const reached = stages.findIndex((s) => s.scope === scope);
  const since = typeof data?.state?.since === "string" ? data.state.since : "";
  const quarantined = overview?.quarantined;

  return (
    <>
      <PageIntro title="Guard">
        The platform's automatic kill switch against runaway AWS cost. CloudWatch alarms and two AWS budgets watch device traffic,
        connections and enrolments; when one fires, the guard cuts things off in stages and emails you. It stays tripped until an
        owner resets it here, so find out why it tripped first.
      </PageIntro>
      {error !== undefined && <Failed error={error} />}
      {loading && !data && <Loading />}

      <Section title="Status">
        {data && (
          <div className={tripped ? "status-hero danger" : "status-hero ok"}>
            <div className="grow">
              <div className="big">{tripped ? `Tripped: ${clip(scope, 20)}` : "Clear"}</div>
              <div className="muted">
                {tripped
                  ? `Since ${when(since)}${since ? ` (${ago(Date.parse(since), now)})` : ""}.`
                  : "Nothing tripped: devices, enrolment and rules run normally."}
              </div>
            </div>
            <ActionButton
              label="Reset guard"
              danger
              tip="Undo a trip: the deny-all policy comes off the fleet groups, the rules are enabled again and the state is cleared."
              confirm={
                "Reset the guard? The deny-all policy comes off the fleet groups (devices reconnect), the configured rules are " +
                "enabled again and the state is cleared. Only do this once you know why it tripped."
              }
              run={async () => (await controller(c, { action: "guard-reset" })).log ?? []}
            />
          </div>
        )}
        {data && Array.isArray(data.state?.reasons) && (data.state.reasons as unknown[]).length > 0 && (
          <>
            <h3>Why it tripped</h3>
            <ul>
              {(data.state.reasons as unknown[]).map((r, i) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: a static list, replaced whole and never reordered
                <li key={i}>{clip(r, 300)}</li>
              ))}
            </ul>
          </>
        )}
        <h3>What a trip does</h3>
        <div className="stages">
          {stages.map((s, i) => (
            <div key={s.scope} className={tripped && i <= reached ? "stage active" : "stage"}>
              <div className="stage-title">
                <span className="step">{i + 1}</span>
                {s.title}
              </div>
              <p>{s.text}</p>
            </div>
          ))}
        </div>
        {data && (
          <details>
            <summary>Raw state</summary>
            <JsonText value={data.state ?? {}} />
          </details>
        )}
      </Section>

      <Section
        title="Alarms"
        tip="Thresholds are 20 times or more above normal traffic, so a firing alarm means something unusual."
        intro="Each alarm trips the guard up to the stage shown. The two budgets (traffic, fleet) work the same way but fire hours later, and a budget already over its limit this month fires again only at 150 %."
      >
        {data &&
          (data.alarms.length === 0 ? (
            <Empty>No guard alarms found.</Empty>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <Th>Alarm</Th>
                    <Th tip="The guard stage this alarm trips when it fires.">Trips</Th>
                    <Th>State</Th>
                    <Th>Since</Th>
                    <Th align="end">Reason</Th>
                  </tr>
                </thead>
                <tbody>
                  {data.alarms.map((a) => {
                    const short = a.AlarmName?.replace(cfg.alarmPrefix, "") ?? "";
                    const info = alarmInfo[short];
                    const state = a.StateValue ?? "";
                    return (
                      <tr key={a.AlarmName}>
                        <td>
                          <div className="cell-main">{info?.[0] ?? short}</div>
                          <div className="cell-sub mono">{a.AlarmName}</div>
                        </td>
                        <td>{info ? <Pill>{info[1]}</Pill> : null}</td>
                        <td>
                          <Pill tone={alarmTone[state] ?? "neutral"}>{alarmLabel[state] ?? state}</Pill>
                        </td>
                        <td className="small nowrap">
                          <span data-tip={when(a.StateUpdatedTimestamp)}>{ago(a.StateUpdatedTimestamp?.getTime(), now)}</span>
                        </td>
                        <td className="small muted">{clip(a.StateReason, 200)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ))}
      </Section>

      <Section
        title="Quarantined devices"
        tip="Single devices cut off by hand on the Groups screen. The guard never quarantines on its own."
      >
        {quarantined instanceof Error ? (
          <Failed error={quarantined} />
        ) : !quarantined || quarantined.size === 0 ? (
          <Empty>No device is quarantined.</Empty>
        ) : (
          <div className="pills">
            {[...quarantined].sort().map((t) => (
              <Pill key={t} tone="danger">
                <span className="mono">{t}</span>
              </Pill>
            ))}
          </div>
        )}
      </Section>
    </>
  );
}
