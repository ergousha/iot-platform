// The portal's configuration: /config.json, written by Terraform (portal.tf).
// Every value is a public fact.

export interface ProductConfig {
  id: string;
  name?: string; // the portal's name for it (Terraform: display_name)
  description?: string;
  fleet: string;
  canary: string;
  excluded: string;
  shadow: string; // the product's named shadow
  legacy?: boolean; // owns registry records without a product attribute
}

export interface Config {
  region: string;
  userPoolId: string;
  userPoolEndpoint: string; // cognito-idp.<region>.amazonaws.com/<pool id>
  clientId: string;
  authOrigin: string; // https://<prefix>.auth.<region>.amazoncognito.com
  identityPoolId: string;
  controllerUrl: string;
  iotDataEndpoint: string;
  registryTable: string;
  registryFields: string[];
  presenceTable: string;
  guardParameter: string;
  claimParameter: string;
  alarmPrefix: string;
  quarantineGroup: string;
  products: ProductConfig[];
}

const strings = [
  "region",
  "userPoolId",
  "userPoolEndpoint",
  "clientId",
  "authOrigin",
  "identityPoolId",
  "controllerUrl",
  "iotDataEndpoint",
  "registryTable",
  "presenceTable",
  "guardParameter",
  "claimParameter",
  "alarmPrefix",
  "quarantineGroup",
] as const;

/** parseConfig checks the shape, so a broken deployment fails loudly. */
export function parseConfig(raw: unknown): Config {
  if (typeof raw !== "object" || raw === null) throw new Error("config.json is not an object");
  const c = raw as Record<string, unknown>;
  for (const k of strings) {
    if (typeof c[k] !== "string" || c[k] === "") throw new Error(`config.json: ${k} is missing`);
  }
  for (const k of ["authOrigin", "controllerUrl"] as const) {
    if (!(c[k] as string).startsWith("https://")) throw new Error(`config.json: ${k} must be https`);
  }
  if (!Array.isArray(c.registryFields) || !c.registryFields.every((f) => typeof f === "string")) {
    throw new Error("config.json: registryFields must be a list of names");
  }
  if (!Array.isArray(c.products) || c.products.length === 0) throw new Error("config.json: no products");
  for (const p of c.products as Record<string, unknown>[]) {
    for (const k of ["id", "fleet", "canary", "excluded", "shadow"]) {
      if (typeof p[k] !== "string" || p[k] === "") throw new Error(`config.json: a product has no ${k}`);
    }
  }
  return c as unknown as Config;
}

/** productName is how the portal names a product: its display name, else its id. */
export function productName(p: ProductConfig | undefined, id = ""): string {
  return p?.name || p?.id || id;
}

/** productById finds a product of the config; undefined for an unknown id. */
export function productById(cfg: Config, id: string): ProductConfig | undefined {
  return cfg.products.find((p) => p.id === id);
}

export async function loadConfig(): Promise<Config> {
  const res = await fetch("/config.json", { cache: "no-cache", credentials: "omit" });
  if (!res.ok) throw new Error(`config.json: HTTP ${res.status}`);
  return parseConfig(await res.json());
}
