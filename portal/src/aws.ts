// AWS access with the signed-in user's identity-pool credentials: direct
// SigV4 reads (every API used here answers CORS preflights), the
// owner's two direct writes (product shadow desired state, canary/excluded
// membership), and the OTA controller's Function URL for everything else.

import { Sha256 } from "@aws-crypto/sha256-js";
import { CloudTrailClient, LookupEventsCommand, type Event as TrailEvent } from "@aws-sdk/client-cloudtrail";
import { CloudWatchClient, DescribeAlarmsCommand, type MetricAlarm } from "@aws-sdk/client-cloudwatch";
import { type AttributeValue, DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import {
  IoTClient,
  type JobExecutionSummaryForThing,
  type JobSummary,
  ListJobExecutionsForThingCommand,
  ListJobsCommand,
  ListThingsInThingGroupCommand,
  UpdateThingGroupsForThingCommand,
} from "@aws-sdk/client-iot";
import { GetThingShadowCommand, IoTDataPlaneClient, UpdateThingShadowCommand } from "@aws-sdk/client-iot-data-plane";
import { GetParameterCommand, ParameterNotFound, SSMClient } from "@aws-sdk/client-ssm";
import { fromCognitoIdentityPool } from "@aws-sdk/credential-provider-cognito-identity";
import { HttpRequest } from "@smithy/protocol-http";
import { SignatureV4 } from "@smithy/signature-v4";
import type { Config, ProductConfig } from "./config";
import { type Item, type Plain, type ProductStatus, unmarshal } from "./data";

type Provider = ReturnType<typeof fromCognitoIdentityPool>;

/**
 * cached reuses identity-pool credentials until five minutes before they
 * expire, so the SDK clients and the Function URL signer share one set
 * instead of each calling Cognito.
 */
function cached(provider: Provider): Provider {
  let current: ReturnType<Provider> | undefined;
  return async () => {
    if (current) {
      const c = await current.catch(() => undefined);
      if (c && (!c.expiration || c.expiration.getTime() - Date.now() > 5 * 60_000)) return c;
    }
    current = provider();
    return current;
  };
}

export interface Clients {
  cfg: Config;
  credentials: Provider;
  iot: IoTClient;
  iotData: IoTDataPlaneClient;
  ddb: DynamoDBClient;
  ssm: SSMClient;
  cw: CloudWatchClient;
  ct: CloudTrailClient;
}

/** clients for one ID token; rebuilt when the token renews. */
export function clients(cfg: Config, idToken: string): Clients {
  const region = cfg.region;
  const credentials = cached(
    fromCognitoIdentityPool({
      clientConfig: { region },
      identityPoolId: cfg.identityPoolId,
      logins: { [cfg.userPoolEndpoint]: idToken },
    }),
  );
  const base = { region, credentials, maxAttempts: 2 };
  return {
    cfg,
    credentials,
    iot: new IoTClient(base),
    iotData: new IoTDataPlaneClient({ ...base, endpoint: `https://${cfg.iotDataEndpoint}` }),
    ddb: new DynamoDBClient(base),
    ssm: new SSMClient(base),
    cw: new CloudWatchClient(base),
    ct: new CloudTrailClient(base),
  };
}

// ---- the OTA controller -----------------------------------------------------

export interface ControllerResult {
  ok: boolean;
  error?: string;
  plan?: string;
  log?: string[];
  status?: unknown;
}

export interface Override {
  action: string;
  product?: string;
  version?: string;
  thing?: string;
  confirm?: string;
}

/** controller POSTs an override to the AWS_IAM Function URL, SigV4-signed. */
export async function controller(c: Clients, o: Override): Promise<ControllerResult> {
  const url = new URL(c.cfg.controllerUrl);
  const body = JSON.stringify(o);
  const signer = new SignatureV4({ service: "lambda", region: c.cfg.region, credentials: c.credentials, sha256: Sha256 });
  const signed = await signer.sign(
    new HttpRequest({
      method: "POST",
      protocol: "https:",
      hostname: url.hostname,
      path: "/",
      headers: { host: url.hostname, "content-type": "application/json" },
      body,
    }),
  );
  const headers: Record<string, string> = { ...signed.headers };
  delete headers.host; // the browser sets it
  const res = await fetch(url.toString(), { method: "POST", headers, body, credentials: "omit", cache: "no-store" });
  let r: ControllerResult;
  try {
    r = (await res.json()) as ControllerResult;
  } catch {
    throw new Error(`controller: HTTP ${res.status}`);
  }
  if (!res.ok || !r.ok) throw new ControllerError(r.error ?? `HTTP ${res.status}`, r.log ?? []);
  return r;
}

export class ControllerError extends Error {
  constructor(
    message: string,
    readonly log: string[],
  ) {
    super(message);
  }
}

export async function productStatus(c: Clients, product: string): Promise<ProductStatus> {
  const r = await controller(c, { action: "status", product });
  return r.status as ProductStatus;
}

// ---- reads ------------------------------------------------------------------

async function scan(c: Clients, table: string, fields?: string[]): Promise<Record<string, Plain>[]> {
  const out: Record<string, Plain>[] = [];
  let start: Record<string, AttributeValue> | undefined;
  // Projected scans are the only ones the roles may run on the registry.
  const projection = fields && {
    Select: "SPECIFIC_ATTRIBUTES" as const,
    ProjectionExpression: fields.map((_, i) => `#f${i}`).join(", "),
    ExpressionAttributeNames: Object.fromEntries(fields.map((f, i) => [`#f${i}`, f])),
  };
  do {
    const page = await c.ddb.send(new ScanCommand({ TableName: table, ExclusiveStartKey: start, ...projection }));
    for (const it of page.Items ?? []) out.push(unmarshal(it as Item));
    start = page.LastEvaluatedKey;
  } while (start);
  return out;
}

export const scanPresence = (c: Clients) => scan(c, c.cfg.presenceTable);
export const scanRegistry = (c: Clients) => scan(c, c.cfg.registryTable, c.cfg.registryFields);

export async function groupThings(c: Clients, group: string): Promise<string[]> {
  const out: string[] = [];
  let nextToken: string | undefined;
  do {
    const page = await c.iot.send(new ListThingsInThingGroupCommand({ thingGroupName: group, nextToken, maxResults: 250 }));
    out.push(...(page.things ?? []));
    nextToken = page.nextToken;
  } while (nextToken);
  return out;
}

/** jsonParameter reads an SSM String holding JSON; undefined when missing. */
export async function jsonParameter(c: Clients, name: string): Promise<Record<string, unknown> | undefined> {
  try {
    const out = await c.ssm.send(new GetParameterCommand({ Name: name }));
    return JSON.parse(out.Parameter?.Value ?? "null") ?? undefined;
  } catch (e) {
    if (e instanceof ParameterNotFound) return undefined;
    throw e;
  }
}

export async function guardAlarms(c: Clients): Promise<MetricAlarm[]> {
  const out = await c.cw.send(new DescribeAlarmsCommand({ AlarmNamePrefix: c.cfg.alarmPrefix, MaxRecords: 50 }));
  return out.MetricAlarms ?? [];
}

/** shadow reads a named shadow; undefined when the device has none. */
export async function shadow(c: Clients, thing: string, name: string): Promise<unknown> {
  try {
    const out = await c.iotData.send(new GetThingShadowCommand({ thingName: thing, shadowName: name }));
    return JSON.parse(new TextDecoder().decode(out.payload));
  } catch (e) {
    if ((e as { name?: string }).name === "ResourceNotFoundException") return undefined;
    throw e;
  }
}

export async function executions(c: Clients, thing: string): Promise<JobExecutionSummaryForThing[]> {
  const out = await c.iot.send(new ListJobExecutionsForThingCommand({ thingName: thing, maxResults: 25 }));
  return out.executionSummaries ?? [];
}

/** productJobs: the product's OTA jobs (ota-<p>-...), newest first. */
export async function productJobs(c: Clients, product: string, limit = 20): Promise<JobSummary[]> {
  const out: JobSummary[] = [];
  let nextToken: string | undefined;
  do {
    const page = await c.iot.send(new ListJobsCommand({ maxResults: 100, nextToken }));
    out.push(...(page.jobs ?? []).filter((j) => j.jobId?.startsWith(`ota-${product}-`)));
    nextToken = page.nextToken;
  } while (nextToken && out.length < 200);
  return out.sort((a, b) => (b.createdAt?.getTime() ?? 0) - (a.createdAt?.getTime() ?? 0)).slice(0, limit);
}

/** Sign-ins of the last week: AssumeRoleWithWebIdentity events. */
export async function signIns(c: Clients): Promise<TrailEvent[]> {
  const out = await c.ct.send(
    new LookupEventsCommand({
      LookupAttributes: [{ AttributeKey: "EventName", AttributeValue: "AssumeRoleWithWebIdentity" }],
      StartTime: new Date(Date.now() - 7 * 24 * 3600 * 1000),
      MaxResults: 50,
    }),
  );
  return out.Events ?? [];
}

/** What one session (access key) did, as CloudTrail recorded it. */
export async function sessionEvents(c: Clients, accessKeyId: string): Promise<TrailEvent[]> {
  const out = await c.ct.send(
    new LookupEventsCommand({
      LookupAttributes: [{ AttributeKey: "AccessKeyId", AttributeValue: accessKeyId }],
      MaxResults: 50,
    }),
  );
  return out.Events ?? [];
}

// ---- the owner's direct writes ----------------------------------------------

/** setDesired sets desired state on the product's own named shadow. */
export async function setDesired(c: Clients, p: ProductConfig, thing: string, desired: Record<string, unknown>): Promise<void> {
  const payload = new TextEncoder().encode(JSON.stringify({ state: { desired } }));
  await c.iotData.send(new UpdateThingShadowCommand({ thingName: thing, shadowName: p.shadow, payload }));
}

export async function moveThing(c: Clients, thing: string, add: string[], remove: string[]): Promise<void> {
  await c.iot.send(
    new UpdateThingGroupsForThingCommand({ thingName: thing, thingGroupsToAdd: add, thingGroupsToRemove: remove }),
  );
}
