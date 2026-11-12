// Sign-in: Cognito managed login, authorization code with PKCE.
//
// Tokens live in memory only (InMemoryWebStorage), so no other script on
// any origin, and no later visitor of this browser profile, can read them.
// Only the PKCE state survives the redirect, in sessionStorage, and it is
// removed on return. A reload signs in again through managed login's
// session cookie; the refresh token renews the session in the background.

import { InMemoryWebStorage, type User, UserManager, WebStorageStateStore } from "oidc-client-ts";
import type { Config } from "./config";

export function userManager(cfg: Config): UserManager {
  const home = `${window.location.origin}/`;
  const issuer = `https://${cfg.userPoolEndpoint}`;
  return new UserManager({
    authority: issuer,
    // Given, not discovered: one fewer origin to trust and fetch.
    metadata: {
      issuer,
      authorization_endpoint: `${cfg.authOrigin}/oauth2/authorize`,
      token_endpoint: `${cfg.authOrigin}/oauth2/token`,
      revocation_endpoint: `${cfg.authOrigin}/oauth2/revoke`,
      userinfo_endpoint: `${cfg.authOrigin}/oauth2/userInfo`,
    },
    client_id: cfg.clientId,
    redirect_uri: home,
    post_logout_redirect_uri: home,
    response_type: "code",
    scope: "openid",
    loadUserInfo: false,
    monitorSession: false,
    automaticSilentRenew: true,
    revokeTokenTypes: ["refresh_token"],
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
  });
}

/** isCallback: managed login has just redirected back with a code. */
export function isCallback(search: string): boolean {
  const q = new URLSearchParams(search);
  return q.has("state") && (q.has("code") || q.has("error"));
}

export type Role = "owner" | "viewer" | "none";

/** role is what the identity pool will grant: the owner group wins. */
export function role(user: User): Role {
  const groups = user.profile["cognito:groups"];
  const list = Array.isArray(groups) ? groups : [];
  if (list.includes("owner")) return "owner";
  if (list.includes("viewer")) return "viewer";
  return "none";
}

export function username(user: User): string {
  const u = user.profile["cognito:username"];
  return typeof u === "string" ? u : "?";
}

/** signOut revokes the refresh token, forgets the user and ends the managed login session. */
export async function signOut(um: UserManager, cfg: Config): Promise<void> {
  try {
    await um.revokeTokens(["refresh_token"]);
  } catch {
    // Already revoked or expired: signing out continues.
  }
  await um.removeUser();
  const q = new URLSearchParams({ client_id: cfg.clientId, logout_uri: `${window.location.origin}/` });
  window.location.assign(`${cfg.authOrigin}/logout?${q.toString()}`);
}
