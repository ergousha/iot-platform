import { useEffect, useState } from "react";
import { sessionEvents, signIns } from "../aws";
import { ago, clip, type Session, session } from "../data";
import { Empty, Failed, Loading, PageIntro, Pill, Section, Th, useLoad, usePortal, when } from "../ui";

// CloudTrail by session tag: each portal sign-in is an
// AssumeRoleWithWebIdentity carrying the Cognito user name; its access key
// then finds what the session did. Overrides run as the OTA controller, and
// the controller's emails name the requesting session's access key. Shadow
// updates are data-plane calls, which CloudTrail management events omit.
export function Audit() {
  const { c, overview } = usePortal();
  const [sessions, error, loading, load] = useLoad<Session[]>();
  const [selected, setSelected] = useState<Session>();
  useEffect(
    () => void load(async () => (await signIns(c)).map((e) => session(e.CloudTrailEvent)).filter((s): s is Session => !!s)),
    [c, load],
  );
  const now = overview?.loadedAt.getTime() ?? 0;

  return (
    <>
      <PageIntro title="Audit">
        Who used the portal. Each sign-in gets short-lived AWS credentials tagged with the user name, and CloudTrail records them.
        Select a session to see the AWS calls it made.
      </PageIntro>
      <Section
        title="Portal sessions, last 7 days"
        tip="From CloudTrail: one row per sign-in or credential renewal (about every hour)."
      >
        {loading && <Loading />}
        {error !== undefined && <Failed error={error} />}
        {sessions && sessions.length === 0 && <Empty>No portal sign-ins recorded.</Empty>}
        {sessions && sessions.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <Th>When</Th>
                  <Th>User</Th>
                  <Th tip="owner: may change things. viewer: read-only.">Role</Th>
                  <Th tip="The session's temporary AWS access key: CloudTrail files every call under it.">Access key</Th>
                  <Th align="end">From IP</Th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => {
                  const isSelected = selected?.accessKeyId === s.accessKeyId;
                  const role = s.role.replace(/^.*-portal-/, "");
                  return (
                    <tr
                      key={s.accessKeyId + s.time}
                      className={isSelected ? "clickable selected" : "clickable"}
                      onClick={() => setSelected(s)}
                      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSelected(s)}
                      tabIndex={0}
                      aria-selected={isSelected}
                    >
                      <td className="nowrap">
                        <div>{ago(Date.parse(s.time), now)}</div>
                        <div className="cell-sub">{when(s.time)}</div>
                      </td>
                      <td className="cell-main">{s.username}</td>
                      <td>
                        <Pill tone={role === "owner" ? "info" : "neutral"}>{role}</Pill>
                      </td>
                      <td className="mono small">{s.accessKeyId}</td>
                      <td className="small mono">{s.sourceIp}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      {selected?.accessKeyId && <SessionEvents key={selected.accessKeyId} s={selected} />}
    </>
  );
}

function SessionEvents({ s }: { s: Session }) {
  const { c } = usePortal();
  const [events, error, loading, load] = useLoad<Awaited<ReturnType<typeof sessionEvents>>>();
  useEffect(() => void load(() => sessionEvents(c, s.accessKeyId)), [c, s.accessKeyId, load]);
  return (
    <Section
      title={`What ${s.username} did`}
      intro={
        <>
          AWS calls made with access key <span className="mono">{s.accessKeyId}</span>. Not listed: shadow reads and writes
          (CloudTrail does not record them) and controller actions, which run as the OTA controller; the controller's emails name
          this access key instead.
        </>
      }
    >
      {loading && <Loading />}
      {error !== undefined && <Failed error={error} />}
      {events &&
        (events.length === 0 ? (
          <Empty>No recorded calls. CloudTrail can take up to 15 minutes to show them.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <Th>When</Th>
                  <Th>Call</Th>
                  <Th>Service</Th>
                  <Th>Resource</Th>
                  <Th align="end">Result</Th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => {
                  let errorCode = "";
                  try {
                    errorCode = JSON.parse(e.CloudTrailEvent ?? "{}").errorCode ?? "";
                  } catch {
                    // unreadable event: shown without its error
                  }
                  return (
                    <tr key={e.EventId}>
                      <td className="small nowrap">{when(e.EventTime)}</td>
                      <td className="cell-main">{e.EventName}</td>
                      <td className="small muted">{e.EventSource?.replace(".amazonaws.com", "")}</td>
                      <td className="small mono">{clip((e.Resources ?? []).map((r) => r.ResourceName).join(", "), 120)}</td>
                      <td>{errorCode ? <Pill tone="danger">{clip(errorCode, 60)}</Pill> : <Pill tone="ok">OK</Pill>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ))}
    </Section>
  );
}
