import express from "express";
import fetch from "node-fetch";
import { createProofJwt, generateDidJwkFromPrivateJwk, ensureOrCreateEcKeyPair, createPkcePair } from "./lib/crypto.js";
import { performPresentation, resolveDeepLinkFromEndpoint } from "./lib/presentation.js";
import { storeWalletCredentialByType, walletRedisClient } from "./lib/cache.js";
import { jwtVerify, decodeJwt, decodeProtectedHeader, createLocalJWKSet, importJWK, importX509 } from "jose";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";
import { verifyMdlToken } from "../utils/mdlVerification.js";

const app = express();
app.use(express.json({ limit: "2mb" }));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// POST /issue
// body: { issuer: string (default http://localhost:3000), offer?: string, fetchOfferPath?: string, credential?: string }
app.post("/issue", async (req, res) => {
  try {
    const issuerBase = (req.body.issuer || "http://localhost:3000").replace(/\/$/, "");
    const deepLink = req.body.offer || (await getOfferDeepLink(issuerBase, req.body.fetchOfferPath, req.body.credential));
    console.log("[/issue] deepLink:", deepLink || "<none>");
    if (!deepLink) {
      return res.status(400).json({ error: "invalid_request", error_description: "Missing offer or fetchOfferPath" });
    }

    const offerConfig = await resolveOfferConfig(deepLink);
    try {
      console.log("[/issue] offer.credential_issuer=", offerConfig?.credential_issuer);
      console.log("[/issue] offer.config_ids=", offerConfig?.credential_configuration_ids);
      console.log("[/issue] offer.grants=", Object.keys(offerConfig?.grants || {}));
      console.log("[/issue] offer full structure:", JSON.stringify(offerConfig, null, 2));
    } catch {}
    const { credential_configuration_ids, grants } = offerConfig;
    const apiBase = (offerConfig.credential_issuer || issuerBase).replace(/\/$/, "");
    const issuerMeta = await discoverIssuerMetadata(apiBase);
    try {
      console.log("[/issue] issuerMeta.token_endpoint=", issuerMeta?.token_endpoint);
      console.log("[/issue] issuerMeta.credential_endpoint=", issuerMeta?.credential_endpoint);
      console.log("[/issue] issuerMeta.nonce_endpoint=", issuerMeta?.nonce_endpoint);
      const cfgKeys = Object.keys(issuerMeta?.credential_configurations_supported || {});
      console.log("[/issue] issuerMeta.credential_configurations_supported keys=", cfgKeys.slice(0, 5), cfgKeys.length > 5 ? `(+${cfgKeys.length - 5} more)` : "");
    } catch {}
    const configurationId = req.body.credential || credential_configuration_ids?.[0];
    if (!configurationId) {
      console.warn("[/issue] no credential_configuration_id available in offer or request.");
      return res.status(400).json({ error: "invalid_request", error_description: "No credential_configuration_id available" });
    }

    const preAuthGrant = grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
    if (!preAuthGrant) {
      console.error("[/issue] OIDC4VCI DRAFT 15 VIOLATION: Only pre-authorized_code grant type supported in this endpoint. Found grants:", Object.keys(grants || {}));
      return res.status(400).json({ error: "unsupported_grant_type", error_description: "Only pre-authorized_code supported" });
    }
    
    console.log("[/issue] invoking pre-authorized issuance. configurationId=", configurationId);
    const result = await runPreAuthorizedIssuance({
      apiBase,
      issuerMeta,
      configurationId,
      preAuthorizedCode: preAuthGrant["pre-authorized_code"],
      txCodeConfig: preAuthGrant.tx_code, // Pass original config
      keyPath: req.body.keyPath,
      pollTimeoutMs: req.body.pollTimeoutMs,
      pollIntervalMs: req.body.pollIntervalMs,
      userPin: req.body.pin, // Pass the pin directly
    });
    return res.json(result);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error", error_description: e.message || String(e) });
  }
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

// GET /session-status/:sessionId
// Returns the current status of a session from Redis
app.get("/session-status/:sessionId", async (req, res) => {
  try {
    const { sessionId } = req.params;
    if (!sessionId) {
      return res.status(400).json({ error: "invalid_request", error_description: "sessionId is required" });
    }

    const key = `wallet:test-session:${sessionId}`;
    const sessionData = await walletRedisClient.get(key);
    
    if (!sessionData) {
      return res.status(404).json({ error: "not_found", error_description: "Session not found" });
    }

    const session = JSON.parse(sessionData);
    return res.json(session);
  } catch (e) {
    console.error("[session-status] error:", e);
    return res.status(500).json({ error: "server_error", error_description: e.message || String(e) });
  }
});

// POST /session
// body: { deepLink: string, sessionId: string, issuer?: string, verifier?: string, credential?: string, keyPath?: string, fetchOfferPath?: string, clientIdScheme?: string, pin?: string }
// - Initializes a test session in Redis with status "pending"
// - If deepLink is openid4vp, runs VP flow (similar to /present)
// - If deepLink is openid-credential-offer (VCI):
//   - If pre-authorized_code grant → run /issue flow (pin used as tx_code if user_pin_required)
//   - If authorization_code grant → run /issue-codeflow flow
// - Updates Redis status to "ok" on success, "failed" on error
app.post("/session", async (req, res) => {
  const { deepLink, sessionId, pin } = req.body || {};
  if (!deepLink || !sessionId) {
    return res.status(400).json({ error: "invalid_request", error_description: "deepLink and sessionId are required" });
  }

  const key = `wallet:test-session:${sessionId}`;
  const ttlInSeconds = parseInt(process.env.WALLET_TEST_SESSION_TTL || "86400");

  async function setStatus(status, extra) {
    const payload = { sessionId, status, ...(extra || {}), updatedAt: new Date().toISOString() };
    try { await walletRedisClient.setEx(key, ttlInSeconds, JSON.stringify(payload)); } catch (e) { console.error("[session-flow] Redis set error", e); }
    return payload;
  }

  await setStatus("pending");

  try {
    // VP request
    if (/^openid4vp:\/\//.test(deepLink)) {
      const verifierBase = (req.body.verifier || "http://localhost:3000").replace(/\/$/, "");
      const result = await performPresentation({ deepLink, verifierBase, credentialType: req.body.credential, keyPath: req.body.keyPath });
      const okPayload = await setStatus("ok", { result: result || { status: "ok" } });
      return res.json(okPayload);
    }

    // VCI request (credential offer)
    if (/^(openid-credential-offer:\/\/|haip:\/\/)/.test(deepLink)) {
      const issuerBaseDefault = (req.body.issuer || "http://localhost:3000").replace(/\/$/, "");
      console.log("[/session] VCI deepLink:", deepLink);
      const offerCfg = await resolveOfferConfig(deepLink);
      const { credential_configuration_ids, grants } = offerCfg;
      const apiBase = (offerCfg.credential_issuer || issuerBaseDefault).replace(/\/$/, "");
      const issuerMeta = await discoverIssuerMetadata(apiBase);
      try {
        console.log("[/session] offer.credential_issuer=", offerCfg?.credential_issuer);
        console.log("[/session] offer.config_ids=", credential_configuration_ids);
        console.log("[/session] offer.grants=", Object.keys(grants || {}));
        console.log("[/session] offer full structure:", JSON.stringify(offerCfg, null, 2));
        console.log("[/session] issuerMeta.token_endpoint=", issuerMeta?.token_endpoint);
        console.log("[/session] issuerMeta.credential_endpoint=", issuerMeta?.credential_endpoint);
        console.log("[/session] issuerMeta.nonce_endpoint=", issuerMeta?.nonce_endpoint);
        const cfgKeys = Object.keys(issuerMeta?.credential_configurations_supported || {});
        console.log("[/session] issuerMeta.credential_configurations_supported keys=", cfgKeys.slice(0, 5), cfgKeys.length > 5 ? `(+${cfgKeys.length - 5} more)` : "");
      } catch {}
      const configurationId = req.body.credential || credential_configuration_ids?.[0];
      if (!configurationId) {
        console.warn("[/session] no credential_configuration_id available in offer or request. Aborting.");
        const failed = await setStatus("failed", { error: "No credential_configuration_id available" });
        return res.status(400).json({ error: "invalid_request", error_description: "No credential_configuration_id available", state: failed });
      }

      // Pre-authorized code flow
      if (grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"]) {
        try {
          const preAuthGrant = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]; 
          console.log("[/session] invoking pre-authorized issuance. configurationId=", configurationId);
          
          const result = await runPreAuthorizedIssuance({
            apiBase,
            issuerMeta,
            configurationId,
            preAuthorizedCode: preAuthGrant["pre-authorized_code"],
            txCodeConfig: preAuthGrant.tx_code, // Pass original config
            keyPath: req.body.keyPath,
            pollTimeoutMs: req.body.pollTimeoutMs,
            pollIntervalMs: req.body.pollIntervalMs,
            userPin: pin, // Pass the pin directly
          });
          const okPayload = await setStatus("ok", { result });
          return res.json(okPayload);
        } catch (err) {
          const failed = await setStatus("failed", { error: err.message || String(err) });
          return res.status(500).json({ error: "server_error", error_description: err.message || String(err), state: failed });
        }
      }

      // Authorization code flow
      if (grants?.authorization_code) {
        if (!grants.authorization_code.issuer_state) {
          console.error("[/session] OIDC4VCI DRAFT 15 VIOLATION: authorization_code grant missing required 'issuer_state' field");
          const failed = await setStatus("failed", { error: "OIDC4VCI DRAFT 15 VIOLATION: authorization_code grant missing required 'issuer_state' field" });
          return res.status(400).json({ error: "invalid_grant", error_description: "OIDC4VCI DRAFT 15 VIOLATION: authorization_code grant missing required 'issuer_state' field", state: failed });
        }
        try {
          const authGrant = grants.authorization_code;
          console.log("[/session] invoking authorization code issuance. configurationId=", configurationId);
          const result = await runAuthorizationCodeIssuance({
            apiBase,
            issuerMeta,
            configurationId,
            issuerState: authGrant.issuer_state,
            keyPath: req.body.keyPath,
            pollTimeoutMs: req.body.pollTimeoutMs,
            pollIntervalMs: req.body.pollIntervalMs,
          });
          const okPayload = await setStatus("ok", { result });
          return res.json(okPayload);
        } catch (err) {
          const failed = await setStatus("failed", { error: err.message || String(err) });
          return res.status(500).json({ error: "server_error", error_description: err.message || String(err), state: failed });
        }
      }

      console.error("[/session] OIDC4VCI DRAFT 15 VIOLATION: No supported grant types found. Supported grants: urn:ietf:params:oauth:grant-type:pre-authorized_code, authorization_code (with issuer_state)");
      const failed = await setStatus("failed", { error: "OIDC4VCI DRAFT 15 VIOLATION: No supported grant types found" });
      return res.status(400).json({ error: "unsupported_grant_type", error_description: "OIDC4VCI DRAFT 15 VIOLATION: No supported grant types found. Supported grants: urn:ietf:params:oauth:grant-type:pre-authorized_code, authorization_code (with issuer_state)", state: failed });
    }

    // Unknown deep link scheme
    const failed = await setStatus("failed", { error: "Unsupported deepLink scheme" });
    return res.status(400).json({ error: "invalid_request", error_description: "Unsupported deepLink scheme", state: failed });
  } catch (e) {
    console.error(e);
    const failed = await setStatus("failed", { error: e.message || String(e) });
    return res.status(500).json({ error: "server_error", error_description: e.message || String(e), state: failed });
  }
});

// POST /present
// body: { verifier?: string (default http://localhost:3000), deepLink?: string, fetchPath?: string, credential?: string (optional), keyPath?: string }
app.post("/present", async (req, res) => {
  try {
    const verifierBase = (req.body.verifier || "http://localhost:3000").replace(/\/$/, "");
    const deepLink = req.body.deepLink || (req.body.fetchPath ? await resolveDeepLinkFromEndpoint(verifierBase, req.body.fetchPath) : undefined);
    if (!deepLink) return res.status(400).json({ error: "invalid_request", error_description: "Missing deepLink or fetchPath" });

    console.log("[/present] resolved deepLink:", deepLink);
    if (req.body.credential) console.log("[/present] hint credential:", req.body.credential);
    if (req.body.keyPath) console.log("[/present] keyPath provided");

    const result = await performPresentation({ deepLink, verifierBase, credentialType: req.body.credential, keyPath: req.body.keyPath });
    return res.json(result || { status: "ok" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error", error_description: e.message || String(e) });
  }
});

// Authorization Code Flow endpoint
// body: { issuer?: string, offer?: string, fetchOfferPath?: string, credential?: string, clientIdScheme?: string }
app.post("/issue-codeflow", async (req, res) => {
  try {
    const issuerBaseInput = (req.body.issuer || "http://localhost:3000").replace(/\/$/, "");
    const deepLink = req.body.offer || (await getOfferDeepLink(issuerBaseInput, req.body.fetchOfferPath, req.body.credential));
    console.log("[/issue-codeflow] deepLink:", deepLink || "<none>");
    if (!deepLink) return res.status(400).json({ error: "invalid_request", error_description: "Missing offer or fetchOfferPath" });

    const offerCfg = await resolveOfferConfig(deepLink);
    try {
      console.log("[/issue-codeflow] offer.credential_issuer=", offerCfg?.credential_issuer);
      console.log("[/issue-codeflow] offer.config_ids=", offerCfg?.credential_configuration_ids);
      console.log("[/issue-codeflow] offer.grants=", Object.keys(offerCfg?.grants || {}));
      console.log("[/issue-codeflow] offer full structure:", JSON.stringify(offerCfg, null, 2));
    } catch {}
    const { credential_configuration_ids, grants } = offerCfg;
    const apiBase = (offerCfg.credential_issuer || issuerBaseInput).replace(/\/$/, "");
    const issuerMeta = await discoverIssuerMetadata(apiBase);
    try {
      console.log("[/issue-codeflow] issuerMeta.token_endpoint=", issuerMeta?.token_endpoint);
      console.log("[/issue-codeflow] issuerMeta.credential_endpoint=", issuerMeta?.credential_endpoint);
      console.log("[/issue-codeflow] issuerMeta.nonce_endpoint=", issuerMeta?.nonce_endpoint);
      const cfgKeys = Object.keys(issuerMeta?.credential_configurations_supported || {});
      console.log("[/issue-codeflow] issuerMeta.credential_configurations_supported keys=", cfgKeys.slice(0, 5), cfgKeys.length > 5 ? `(+${cfgKeys.length - 5} more)` : "");
    } catch {}

    // Expect authorization_code grant
    const authGrant = grants?.authorization_code;
    if (!authGrant) {
      console.error("[/issue-codeflow] OIDC4VCI DRAFT 15 VIOLATION: authorization_code grant type required in this endpoint. Found grants:", Object.keys(grants || {}));
      return res.status(400).json({ error: "unsupported_grant_type", error_description: "authorization_code grant required" });
    }
    if (!authGrant.issuer_state) {
      console.error("[/issue-codeflow] OIDC4VCI DRAFT 15 VIOLATION: authorization_code grant missing required 'issuer_state' field");
      return res.status(400).json({ error: "unsupported_grant_type", error_description: "authorization_code grant with issuer_state required" });
    }

    const configurationId = req.body.credential || credential_configuration_ids?.[0];
    if (!configurationId) return res.status(400).json({ error: "invalid_request", error_description: "No credential_configuration_id available" });

    const result = await runAuthorizationCodeIssuance({
      apiBase,
      issuerMeta,
      configurationId,
      issuerState: authGrant.issuer_state,
      keyPath: req.body.keyPath,
      pollTimeoutMs: req.body.pollTimeoutMs,
      pollIntervalMs: req.body.pollIntervalMs,
    });
    return res.json(result);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error", error_description: e.message || String(e) });
  }
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Wallet service listening on http://localhost:${port}`));

async function getOfferDeepLink(issuerBase, path, credentialType) {
  if (!path) return undefined;
  const url = new URL(issuerBase + path);
  if (credentialType) url.searchParams.set("type", credentialType);
  console.log("[offer] GET", url.toString());
  const res = await fetch(url.toString());
  console.log("[offer] <-", res.status);
  if (!res.ok) throw new Error(`Fetch-offer error ${res.status}`);
  const body = await res.json();
  return body.deepLink;
}

async function resolveOfferConfig(deepLink) {
  const url = new URL(deepLink.replace(/^haip:\/\//, "openid-credential-offer://"));
  if (url.protocol !== "openid-credential-offer:") throw new Error("Unsupported offer scheme");
  const encoded = url.searchParams.get("credential_offer_uri");
  if (!encoded) throw new Error("Missing credential_offer_uri in offer");
  const offerUri = decodeURIComponent(encoded);
  console.log("[offer] fetching credential_offer_uri:", offerUri);
  const res = await fetch(offerUri);
  console.log("[offer] credential_offer_uri status:", res.status);
  if (!res.ok) throw new Error(`Offer-config error ${res.status}`);
  return res.json();
}

async function discoverIssuerMetadata(credentialIssuerBase) {
  const base = credentialIssuerBase.replace(/\/$/, "");
  // RFC: if credential_issuer contains a path, well-known URI keeps path suffix
  let origin, path;
  try {
    const u = new URL(base);
    origin = u.origin;
    path = u.pathname.replace(/\/$/, "");
  } catch {
    origin = base; path = "";
  }
  const candidates = [
    `${origin}/.well-known/openid-credential-issuer${path}`,
    `${base}/.well-known/openid-credential-issuer`,
  ];
  let meta = null; let lastErr = null;
  console.log("[issuer-meta] trying candidates:", candidates);
  for (const url of candidates) {
    try {
      const res = await fetch(url);
      console.log("[issuer-meta]", url, "->", res.status);
      if (res.ok) { meta = await res.json(); console.log("[issuer-meta] selected:", url); break; }
      lastErr = res.status;
    } catch (e) { lastErr = e.message || String(e); }
  }
  if (!meta) throw new Error(`Issuer metadata fetch error ${lastErr}`);
  // Normalize property names that can differ across specs/implementations
  // Prefer token_endpoint, credential_endpoint, nonce_endpoint, credential_deferred_endpoint
  if (!meta.credential_deferred_endpoint && meta.deferred_credential_endpoint) {
    meta.credential_deferred_endpoint = meta.deferred_credential_endpoint;
  }
  // Some issuers expose authorization_servers (array) instead of authorization_server
  if (!meta.authorization_server && Array.isArray(meta.authorization_servers) && meta.authorization_servers.length > 0) {
    meta.authorization_server = meta.authorization_servers[0];
  }
  try {
    console.log("[issuer-meta] summary: token=", meta?.token_endpoint, "credential=", meta?.credential_endpoint, "nonce=", meta?.nonce_endpoint, "deferred=", meta?.credential_deferred_endpoint, "authz_server=", meta?.authorization_server);
  } catch {}
  return meta;
}

async function discoverAuthorizationServerMetadata(authorizationServerBase) {
  // RFC 8414: If issuer has path component, well-known is host + '/.well-known/oauth-authorization-server' + path
  const baseStr = authorizationServerBase.replace(/\/$/, "");
  let origin, path;
  try {
    const u = new URL(baseStr);
    origin = u.origin;
    path = u.pathname.replace(/\/$/, "");
  } catch {
    // Not a full URL, fallback to direct
    origin = baseStr;
    path = "";
  }

  const candidates = [
    `${origin}/.well-known/oauth-authorization-server${path}`,
    `${origin}/.well-known/openid-configuration${path}`,
    `${baseStr}/.well-known/oauth-authorization-server`,
    `${baseStr}/.well-known/openid-configuration`,
  ];

  let lastErr = null;
  console.log("[as-meta] trying candidates:", candidates);
  for (const url of candidates) {
    try {
      const res = await fetch(url);
      console.log("[as-meta]", url, "->", res.status);
      if (res.ok) { console.log("[as-meta] selected:", url); return res.json(); }
      lastErr = res.status;
    } catch (e) {
      lastErr = e.message || String(e);
    }
  }
  throw new Error(`AS metadata fetch error ${lastErr}`);
}

function makeTxCode(cfg) {
  if (cfg?.input_mode === "numeric" && typeof cfg?.length === "number") {
    return "".padStart(cfg.length, "1");
  }
  return undefined;
}

async function httpPostJson(url, body) {
  const start = Date.now();
  try { console.log("[http] POST JSON ->", url); } catch {}
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) });
  try { console.log("[http] <-", url, res.status, (Date.now() - start) + "ms"); } catch {}
  return res;
}

async function httpPostForm(url, params) {
  const form = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => { if (typeof v !== 'undefined' && v !== null) form.set(k, String(v)); });
  const start = Date.now();
  try { console.log("[http] POST FORM ->", url); } catch {}
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() });
  try { console.log("[http] <-", url, res.status, (Date.now() - start) + "ms"); } catch {}
  return res;
}

async function forwardError(res, upstreamResponse, defaultCode) {
  let payload = null;
  try { payload = await upstreamResponse.json(); } catch {}
  return res.status(upstreamResponse.status).json(payload || { error: defaultCode, status: upstreamResponse.status });
}

function randomState() {
  return Math.random().toString(36).slice(2);
}

function safeParseJson(str) {
  try { return JSON.parse(str); } catch { return null; }
}

async function runPreAuthorizedIssuance({ apiBase, issuerMeta, configurationId, preAuthorizedCode, txCodeConfig, keyPath, pollTimeoutMs, pollIntervalMs, userPin }) {
  // Only use tx_code if userPin is provided (per OIDC4VCI spec)
  let txCode = undefined;
  if (userPin) {
    txCode = userPin;
    console.log("[preauth] using provided userPin for tx_code");
  }
  // If no userPin, don't send tx_code (issuer will handle missing tx_code appropriately)
  let tokenEndpoint = issuerMeta.token_endpoint || null;
  // If token_endpoint is not in issuer metadata, try authorization server metadata per RFC 8414
  if (!tokenEndpoint && (issuerMeta.authorization_server || (Array.isArray(issuerMeta.authorization_servers) && issuerMeta.authorization_servers.length))) {
    const asBase = issuerMeta.authorization_server || issuerMeta.authorization_servers[0];
    try {
      const asMeta = await discoverAuthorizationServerMetadata(asBase);
      tokenEndpoint = asMeta.token_endpoint;
      console.log("[preauth] tokenEndpoint discovered via AS:", tokenEndpoint);
    } catch (e) {
      console.warn("[preauth] AS metadata discovery failed:", e?.message || e);
    }
  }
  tokenEndpoint = tokenEndpoint || `${apiBase}/token_endpoint`;
  console.log("[preauth] apiBase=", apiBase, "configurationId=", configurationId);
  console.log("[preauth] tokenEndpoint=", tokenEndpoint);
  console.log("[preauth] requesting token...");
  const tokenRes = await httpPostForm(tokenEndpoint, {
    grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": preAuthorizedCode,
    ...(txCode ? { tx_code: txCode } : {}),
  });
  console.log("[preauth] tokenRes.status=", tokenRes.status);
  if (!tokenRes.ok) {
    const text = await tokenRes.text().catch(() => "");
    console.error("[preauth] token error", tokenRes.status, text?.slice(0, 500));
    let err = {};
    try { err = JSON.parse(text); } catch {}
    throw new Error(`token_error ${tokenRes.status}: ${JSON.stringify(err)}`);
  }
  const tokenBody = await tokenRes.json();
  const accessToken = tokenBody.access_token;
  let c_nonce = tokenBody.c_nonce;
  console.log("[preauth] got access_token=", accessToken ? "yes" : "no", "c_nonce=", c_nonce ? "yes" : "no");
  if (c_nonce) {
    console.log("[preauth] using c_nonce from token response");
  } else if (issuerMeta.nonce_endpoint) {
    const nonceEndpoint = issuerMeta.nonce_endpoint;
    console.log("[preauth] nonceEndpoint=", nonceEndpoint);
    const nonceRes = await httpPostJson(nonceEndpoint, {});
    if (!nonceRes.ok) {
      const text = await nonceRes.text().catch(() => "");
      console.error("[preauth] nonce error", nonceRes.status, text?.slice(0, 500));
      let err = {};
      try { err = JSON.parse(text); } catch {}
      throw new Error(`nonce_error ${nonceRes.status}: ${JSON.stringify(err)}`);
    }
    const nonceJson = await nonceRes.json();
    c_nonce = nonceJson.c_nonce;
  } else {
    console.log("[preauth] no c_nonce in token and no nonce_endpoint; proceeding without nonce");
  }

  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath);
  const didJwk = generateDidJwkFromPrivateJwk(publicJwk);
  const proofJwt = await createProofJwt({ privateJwk, publicJwk, audience: apiBase, nonce: c_nonce, issuer: didJwk });
  try { console.log("[preauth] proof JWT created. len=", proofJwt?.length || 0); } catch {}

  const credentialEndpoint = issuerMeta.credential_endpoint || `${apiBase}/credential`;
  console.log("[preauth] credentialEndpoint=", credentialEndpoint);
  console.log("[preauth] requesting credential...");
  const credReq = { credential_configuration_id: configurationId, proof: { proof_type: "jwt", jwt: proofJwt } };
  console.log("[preauth] credential request:", JSON.stringify(credReq, null, 2));
  console.log("[preauth] access_token preview:", accessToken.substring(0, 20) + "...");
  
  const credRes = await fetch(credentialEndpoint, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
    body: JSON.stringify(credReq),
  });
  console.log("[preauth] credentialRes.status=", credRes.status);

  if (!credRes.ok) {
    const text = await credRes.text().catch(() => "");
    console.error("[preauth] credential error", credRes.status);
    console.error("[preauth] credential error response headers:", Object.fromEntries(credRes.headers.entries()));
    console.error("[preauth] credential error response body:", text);
    
    let err = {};
    try { 
      err = JSON.parse(text); 
      console.error("[preauth] credential error parsed JSON:", JSON.stringify(err, null, 2));
    } catch (parseErr) {
      console.error("[preauth] credential error response is not JSON, raw text:", text);
    }
    
    throw new Error(`credential_error ${credRes.status}: ${JSON.stringify(err)}`);
  }

  if (credRes.status === 202) {
    const { transaction_id } = await credRes.json();
    const start = Date.now();
    const timeout = pollTimeoutMs ?? 30000;
    const interval = pollIntervalMs ?? 2000;
    const deferredEndpoint = issuerMeta.credential_deferred_endpoint || `${apiBase}/credential_deferred`;
    while (Date.now() - start < timeout) {
      await sleep(interval);
      const defRes = await httpPostJson(deferredEndpoint, { transaction_id });
      console.log("[preauth] deferred poll ->", defRes.status);
      if (defRes.ok) {
        const body = await defRes.json();
        await validateAndStoreCredential({ configurationId, credential: body, issuerMeta, apiBase, keyBinding: { privateJwk, publicJwk, didJwk }, metadata: { configurationId, c_nonce } });
        return body;
      }
    }
    throw new Error("timeout: Deferred issuance timed out");
  }

  if (!credRes.ok) {
    const err = await credRes.json().catch(() => ({}));
    throw new Error(`credential_error ${credRes.status}: ${JSON.stringify(err)}`);
  }
  const credBody = await credRes.json();
  await validateAndStoreCredential({ configurationId, credential: credBody, issuerMeta, apiBase, keyBinding: { privateJwk, publicJwk, didJwk }, metadata: { configurationId, c_nonce } });
  return credBody;
}

async function runAuthorizationCodeIssuance({ apiBase, issuerMeta, configurationId, issuerState, keyPath, pollTimeoutMs, pollIntervalMs }) {
  // Discover authorization endpoint
  let authorizeEndpoint = issuerMeta.authorization_endpoint || null;
  let tokenEndpointFromAS = null;
  if (!authorizeEndpoint && issuerMeta.authorization_server) {
    const asMeta = await discoverAuthorizationServerMetadata(issuerMeta.authorization_server);
    authorizeEndpoint = asMeta.authorization_endpoint;
    tokenEndpointFromAS = asMeta.token_endpoint;
  }
  const authorizeUrl = new URL((authorizeEndpoint || apiBase + "/authorize"));
  const { codeVerifier, codeChallenge, codeChallengeMethod } = createPkcePair();
  const state = randomState();
  const redirectUri = "openid4vp://";

  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("issuer_state", issuerState);
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("client_id", "wallet-client");
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", codeChallengeMethod);
  authorizeUrl.searchParams.set("scope", configurationId);

  console.log("[codeflow] authorizeUrl:", authorizeUrl.toString());
  const authRes = await fetch(authorizeUrl.toString(), { redirect: "manual" });
  console.log("[codeflow] authRes.status:", authRes.status);
  console.log("[codeflow] authRes.headers:", Object.fromEntries(authRes.headers.entries()));
  
  let redirectUrl = authRes.headers.get("location");
  console.log("[codeflow] redirectUrl from headers:", redirectUrl);
  
  if (!redirectUrl) {
    const bodyText = await authRes.text().catch(() => "");
    console.log("[codeflow] authRes body:", bodyText);
    const redirectPayload = safeParseJson(bodyText);
    console.log("[codeflow] parsed redirect payload:", redirectPayload);
    if (redirectPayload?.redirect_uri) redirectUrl = redirectPayload.redirect_uri;
    else if (/^openid4vp:\/\//.test(bodyText)) redirectUrl = bodyText;
  }
  
  if (!redirectUrl) {
    console.error("[codeflow] No redirect URL found. Status:", authRes.status);
    throw new Error(`authorize_error ${authRes.status}: No redirect URL found`);
  }
  console.log("[codeflow] redirectUrl:", redirectUrl);
  const redirect = new URL(redirectUrl);
  const code = redirect.searchParams.get("code");
  if (!code) throw new Error("invalid_response: Authorization code missing");

  let tokenEndpoint = issuerMeta.token_endpoint || tokenEndpointFromAS || `${apiBase}/token_endpoint`;
  console.log("[codeflow] apiBase=", apiBase, "configurationId=", configurationId);
  console.log("[codeflow] tokenEndpoint=", tokenEndpoint);
  console.log("[codeflow] requesting token...");
  const tokenRes = await httpPostForm(tokenEndpoint, { grant_type: "authorization_code", code, code_verifier: codeVerifier });
  console.log("[codeflow] tokenRes.status=", tokenRes.status);
  if (!tokenRes.ok) {
    const text = await tokenRes.text().catch(() => "");
    console.error("[codeflow] token error", tokenRes.status, text?.slice(0, 500));
    let err = {};
    try { err = JSON.parse(text); } catch {}
    throw new Error(`token_error ${tokenRes.status}: ${JSON.stringify(err)}`);
  }
  const tokenBody = await tokenRes.json();
  const accessToken = tokenBody.access_token;
  let c_nonce = tokenBody.c_nonce;
  console.log("[codeflow] got access_token=", accessToken ? "yes" : "no", "c_nonce=", c_nonce ? "yes" : "no");
  if (c_nonce) {
    console.log("[codeflow] using c_nonce from token response");
  } else if (issuerMeta.nonce_endpoint) {
    const nonceEndpoint = issuerMeta.nonce_endpoint;
    console.log("[codeflow] nonceEndpoint=", nonceEndpoint);
    const nonceRes = await httpPostJson(nonceEndpoint, {});
    if (!nonceRes.ok) {
      const text = await nonceRes.text().catch(() => "");
      console.error("[codeflow] nonce error", nonceRes.status, text?.slice(0, 500));
      let err = {};
      try { err = JSON.parse(text); } catch {}
      throw new Error(`nonce_error ${nonceRes.status}: ${JSON.stringify(err)}`);
    }
    const nonceJson = await nonceRes.json();
    c_nonce = nonceJson.c_nonce;
  } else {
    console.log("[codeflow] no c_nonce in token and no nonce_endpoint; proceeding without nonce");
  }

  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath);
  const didJwk = generateDidJwkFromPrivateJwk(publicJwk);
  const proofJwt = await createProofJwt({ privateJwk, publicJwk, audience: apiBase, nonce: c_nonce, issuer: didJwk });

  const credentialEndpoint = issuerMeta.credential_endpoint || `${apiBase}/credential`;
  console.log("[codeflow] credentialEndpoint=", credentialEndpoint);
  console.log("[codeflow] requesting credential...");
  const credReq = { credential_configuration_id: configurationId, proof: { proof_type: "jwt", jwt: proofJwt } };
  const credRes = await fetch(credentialEndpoint, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
    body: JSON.stringify(credReq),
  });
  console.log("[codeflow] credentialRes.status=", credRes.status);

  if (credRes.status === 202) {
    const { transaction_id } = await credRes.json();
    const start = Date.now();
    const timeout = pollTimeoutMs ?? 30000;
    const interval = pollIntervalMs ?? 2000;
    const deferredEndpoint = issuerMeta.credential_deferred_endpoint || `${apiBase}/credential_deferred`;
    while (Date.now() - start < timeout) {
      await sleep(interval);
      const defRes = await httpPostJson(deferredEndpoint, { transaction_id });
      if (defRes.ok) {
        const body = await defRes.json();
        await validateAndStoreCredential({ configurationId, credential: body, issuerMeta, apiBase, keyBinding: { privateJwk, publicJwk, didJwk }, metadata: { configurationId, c_nonce } });
        return body;
      }
    }
    throw new Error("timeout: Deferred issuance timed out");
  }

  if (!credRes.ok) {
    const err = await credRes.json().catch(() => ({}));
    throw new Error(`credential_error ${credRes.status}: ${JSON.stringify(err)}`);
  }
  const credBody = await credRes.json();
  await validateAndStoreCredential({ configurationId, credential: credBody, issuerMeta, apiBase, keyBinding: { privateJwk, publicJwk, didJwk }, metadata: { configurationId, c_nonce } });
  return credBody;
}

async function validateAndStoreCredential({ configurationId, credential, issuerMeta, apiBase, keyBinding, metadata }) {
  // Extract the token string if envelope is used
  const token = extractCredentialToken(credential);
  if (!token) throw new Error("credential_format_error: could not locate credential token");

  console.log("[validate] configurationId=", configurationId, "issuer=", issuerMeta?.credential_issuer, "has.c_nonce=", !!metadata?.c_nonce);
  console.log("[validate] token preview:", typeof token === 'string' ? token.substring(0, 60) + "..." : typeof token);
  try {
    const dbgFull = process.env.WALLET_DEBUG_CREDENTIAL === 'full';
    const envelopeStr = typeof credential === 'string' ? credential : JSON.stringify(credential);
    const shown = dbgFull ? envelopeStr : envelopeStr.substring(0, 2000);
    console.log("[validate] credential envelope (" + (dbgFull ? "full" : "truncated") + ", len=" + envelopeStr.length + "):", shown);
  } catch {}

  // Try SD-JWT first (presence of '~'), else treat as JWT VC; if neither, try mdoc
  if (typeof token === 'string' && token.includes('~')) {
    await validateSdJwt({ sdJwt: token, issuerMeta, configurationId, expectedCNonce: metadata?.c_nonce });
  } else if (typeof token === 'string' && token.split('.').length >= 3) {
    await validateJwtVc({ jwtVc: token, issuerMeta, apiBase, configurationId, publicJwk: keyBinding?.publicJwk });
  } else if (typeof token === 'string') {
    // Potential mdoc base64url
    const mdocResult = await verifyMdlToken(token, { validateStructure: true, includeMetadata: false });
    if (!mdocResult.success) throw new Error(`mdoc_validation_failed: ${mdocResult.error}`);
    // Placeholder for cryptographic verification using trust anchors
    if (process.env.WALLET_MDL_STRICT === 'true') {
      throw new Error("mdoc_crypto_verification_not_implemented: provide trust anchors and crypto verifier");
    }
  }

  // If validation passed, store
  await storeWalletCredentialByType(configurationId, { credential, keyBinding, metadata });
}

function extractCredentialToken(credentialEnvelope) {
  if (!credentialEnvelope) return null;
  if (typeof credentialEnvelope === 'string') return credentialEnvelope;
  if (credentialEnvelope.credential && typeof credentialEnvelope.credential === 'string') return credentialEnvelope.credential;
  if (credentialEnvelope.credentials) {
    for (const value of Object.values(credentialEnvelope.credentials)) {
      if (typeof value === 'string') return value;
      if (value && typeof value === 'object') {
        for (const sub of Object.values(value)) {
          if (typeof sub === 'string') return sub;
        }
      }
    }
  }
  for (const v of Object.values(credentialEnvelope)) {
    if (typeof v === 'string') return v;
  }
  return null;
}

async function validateSdJwt({ sdJwt, issuerMeta, configurationId, expectedCNonce }) {
  console.log("[sd-jwt] start validation; configurationId=", configurationId);
  // Decode and reconstruct claims (verifies disclosures/digests)
  const decoded = await decodeSdJwt(sdJwt, digest);
  console.log("[sd-jwt] decoded header.alg=", decoded.jwt.header?.alg, "kid=", decoded.jwt.header?.kid);
  // Throws if disclosures invalid
  await getClaims(decoded.jwt.payload, decoded.disclosures, digest);
  console.log("[sd-jwt] disclosures/digests verified; vct=", decoded.jwt.payload?.vct);

  // Extract JWS and header once
  const jws = sdJwt.split('~')[0];
  let hdr = {};
  try { hdr = decodeProtectedHeader(jws); } catch {}
  let signatureVerified = false;
  // DID-based signature verification (did:web, did:jwk)
  if ((hdr.kid && hdr.kid.startsWith('did:')) || (decoded.jwt.payload?.iss && String(decoded.jwt.payload.iss).startsWith('did:'))) {
    try {
      const didIssuer = (hdr.kid && hdr.kid.split('#')[0]) || String(decoded.jwt.payload.iss);
      console.log("[sd-jwt] attempting DID-based verification using", didIssuer);
      await verifyJwsWithDid(jws, hdr, decoded.jwt.payload?.iss);
      console.log("[sd-jwt] DID-based JWS signature verified");
      signatureVerified = true;
    } catch (e) {
      console.warn("[sd-jwt] DID-based verification failed:", e?.message || e);
    }
  }
  // If x5c present, try x509 cert verification (only if not already verified)
  if (!signatureVerified && Array.isArray(hdr.x5c) && hdr.x5c.length > 0) {
    const pem = base64DerToPem(hdr.x5c[0]);
    try {
      const certKey = await importX509(pem, hdr.alg || 'ES256');
      await jwtVerify(jws, certKey);
      console.log("[sd-jwt] JWS signature verified via x5c certificate");
      signatureVerified = true;
    } catch (e) {
      console.warn("[sd-jwt] x5c certificate verification failed:", e?.message || e);
    }
  }

  // Verify issuer signature of SD-JWT JWS
  const jwksUrl = issuerMeta?.jwks_uri || (issuerMeta?.credential_issuer ? `${issuerMeta.credential_issuer.replace(/\/$/, '')}/.well-known/jwt-vc-issuer` : null);
  if (!signatureVerified && jwksUrl) {
    console.log("[sd-jwt] fetching JWKS from:", jwksUrl);
    const res = await fetch(jwksUrl);
    console.log("[sd-jwt] JWKS fetch status:", res.status);
    if (res.ok) {
      const body = await res.json();
      const jwks = body.keys ? body : body.jwks ? body.jwks : null;
      console.log("[sd-jwt] JWKS keys count:", jwks?.keys?.length || (Array.isArray(jwks) ? jwks.length : 0));
      if (jwks) {
        // hdr and jws are already computed above
        console.log("[sd-jwt] JWS header.alg=", hdr.alg, "kid=", hdr.kid);
        const JWKS = createLocalJWKSet(jwks);
        try {
          await jwtVerify(jws, JWKS);
          console.log("[sd-jwt] JWS signature verified");
          signatureVerified = true;
        } catch (e) {
          console.error("[sd-jwt] JWS signature verification failed with JWKS resolver:", e?.message || e);
          // Fallback: iterate keys if no kid or resolver failed
          const keysArr = Array.isArray(jwks.keys) ? jwks.keys : jwks.keys ? jwks.keys : jwks;
          if (Array.isArray(keysArr) && keysArr.length > 0) {
            let verified = false;
            for (const [idx, jwk] of keysArr.entries()) {
              if (jwk.use && jwk.use !== 'sig') continue;
              if (jwk.kty && jwk.kty !== 'EC') continue;
              try {
                console.log(`[sd-jwt] Trying key[${idx}] kid=${jwk.kid || 'none'} crv=${jwk.crv}`);
                const key = await importJWK(jwk, hdr.alg || 'ES256');
                await jwtVerify(jws, key);
                console.log(`[sd-jwt] Verified with key[${idx}]`);
                verified = true;
                break;
              } catch (err) {
                console.warn(`[sd-jwt] key[${idx}] failed:`, err?.message || err);
              }
            }
            if (!verified) throw new Error('signature verification failed');
            signatureVerified = true;
          } else {
            throw new Error('signature verification failed');
          }
        }
      }
    } else {
      console.warn("[sd-jwt] JWKS fetch failed; skipping JWS verification");
    }
  }

  if (!signatureVerified) {
    throw new Error('signature verification failed');
  }

  // Validate kb-jwt binding and c_nonce
  if (decoded.kbJwt && expectedCNonce) {
    try {
      const kbDecoded = decodeJwt(decoded.kbJwt);
      console.log("[sd-jwt] kb-jwt nonce=", kbDecoded?.nonce, "expected=", expectedCNonce);
      if (kbDecoded?.nonce && kbDecoded.nonce !== expectedCNonce) {
        throw new Error("kb_jwt_nonce_mismatch");
      }
    } catch (e) {
      // If decode fails, do a soft fail
      console.error("[sd-jwt] kb-jwt decode failed:", e?.message || e);
      throw new Error("kb_jwt_decode_failed");
    }
  }

  // Ensure the credential matches expected configuration
  checkClaimsAgainstConfig({
    tokenClaims: decoded.jwt.payload,
    issuerMeta,
    configurationId,
    formatHint: "sd-jwt"
  });
}

async function validateJwtVc({ jwtVc, issuerMeta, apiBase, configurationId, publicJwk }) {
  console.log("[jwt-vc] start validation; configurationId=", configurationId);
  try {
    const hdr = decodeProtectedHeader(jwtVc);
    console.log("[jwt-vc] header.alg=", hdr.alg, "kid=", hdr.kid);
    // DID-based verification first if kid/iss is DID
    if ((hdr.kid && hdr.kid.startsWith('did:')) || (issuerMeta?.credential_issuer?.startsWith('did:') || false)) {
      try {
        const didIssuer = (hdr.kid && hdr.kid.split('#')[0]) || issuerMeta?.credential_issuer;
        console.log("[jwt-vc] attempting DID-based verification using", didIssuer);
        const verified = await verifyJwsWithDid(jwtVc, hdr, didIssuer);
        var payloadFromDid = verified?.payload;
        if (payloadFromDid) console.log("[jwt-vc] signature verified via DID");
      } catch (e) {
        console.warn("[jwt-vc] DID-based verification failed:", e?.message || e);
      }
    }
    if (Array.isArray(hdr.x5c) && hdr.x5c.length > 0) {
      const pem = base64DerToPem(hdr.x5c[0]);
      try {
        const certKey = await importX509(pem, hdr.alg || 'ES256');
        const verified = await jwtVerify(jwtVc, certKey);
        console.log("[jwt-vc] signature verified via x5c certificate");
        // Use payload from verified path
        var payloadFromX5c = verified.payload;
      } catch (e) {
        console.warn("[jwt-vc] x5c certificate verification failed:", e?.message || e);
      }
    }
  } catch {}
  // Validate JWT VC signature using issuer JWKS
  const jwksUrl = issuerMeta?.jwks_uri || `${apiBase}/jwks`;
  let payload = typeof payloadFromDid !== 'undefined' ? payloadFromDid : (typeof payloadFromX5c !== 'undefined' ? payloadFromX5c : undefined);
  if (jwksUrl) {
    console.log("[jwt-vc] fetching JWKS from:", jwksUrl);
    const res = await fetch(jwksUrl);
    console.log("[jwt-vc] JWKS fetch status:", res.status);
    if (res.ok) {
      const jwks = await res.json();
      const keysCount = jwks?.keys?.length || 0;
      console.log("[jwt-vc] JWKS keys count:", keysCount);
      if (!payload) {
        const JWKS = createLocalJWKSet(jwks.keys ? jwks : { keys: jwks.keys || [] });
        try {
          const verified = await jwtVerify(jwtVc, JWKS);
          payload = verified.payload;
          console.log("[jwt-vc] signature verified");
        } catch (e) {
          console.error("[jwt-vc] signature verification failed with JWKS resolver:", e?.message || e);
          // Fallback: iterate keys
          const hdr2 = (()=>{ try { return decodeProtectedHeader(jwtVc); } catch { return {}; } })();
          const keysArr = Array.isArray(jwks.keys) ? jwks.keys : jwks.keys ? jwks.keys : jwks;
          if (Array.isArray(keysArr) && keysArr.length > 0) {
            for (const [idx, jwk] of keysArr.entries()) {
              if (jwk.use && jwk.use !== 'sig') continue;
              try {
                console.log(`[jwt-vc] Trying key[${idx}] kid=${jwk.kid || 'none'} alg=${hdr2.alg}`);
                const key = await importJWK(jwk, hdr2.alg || 'ES256');
                const verified = await jwtVerify(jwtVc, key);
                payload = verified.payload;
                console.log(`[jwt-vc] Verified with key[${idx}]`);
                break;
              } catch (err) {
                console.warn(`[jwt-vc] key[${idx}] failed:`, err?.message || err);
              }
            }
            if (!payload) throw new Error('signature verification failed');
          } else {
            throw new Error('signature verification failed');
          }
        }
      }
    } else {
      console.warn("[jwt-vc] JWKS fetch failed; will decode without verify");
    }
  }
  if (!payload) payload = decodeJwt(jwtVc);

  // iss must match credential_issuer
  if (issuerMeta?.credential_issuer && payload?.iss && payload.iss !== issuerMeta.credential_issuer) {
    console.error("[jwt-vc] issuer mismatch:", payload.iss, "!=", issuerMeta.credential_issuer);
    throw new Error("issuer_mismatch");
  }

  // Ensure typ/vct matches expected configuration
  checkClaimsAgainstConfig({ tokenClaims: payload, issuerMeta, configurationId, formatHint: "jwt_vc_json" });

  // If cnf/sub_jwk is present, ensure it matches wallet public key
  const presentedJwk = payload?.cnf?.jwk || payload?.sub_jwk;
  if (presentedJwk && publicJwk && !jwkEquals(publicJwk, presentedJwk)) {
    console.error("[jwt-vc] holder binding mismatch. walletJwk.x=", publicJwk?.x, "presentedJwk.x=", presentedJwk?.x);
    throw new Error("holder_binding_mismatch");
  }
}

function checkClaimsAgainstConfig({ tokenClaims, issuerMeta, configurationId, formatHint }) {
  const cfg = issuerMeta?.credential_configurations_supported?.[configurationId];
  if (!cfg) return; // No config to check against
  // For SD-JWT, expect vct in payload
  const tokenVct = tokenClaims?.vct || tokenClaims?.vc?.type || tokenClaims?.credential_type;
  const expectedVct = cfg?.vct || cfg?.credential_definition?.type || cfg?.credential_definition?.types || cfg?.type;
  if (Array.isArray(expectedVct)) {
    if (Array.isArray(tokenVct)) {
      const ok = tokenVct.some((t) => expectedVct.includes(t));
      if (!ok) throw new Error("credential_type_mismatch");
    } else if (tokenVct && !expectedVct.includes(tokenVct)) {
      throw new Error("credential_type_mismatch");
    }
  } else if (expectedVct && tokenVct && expectedVct !== tokenVct && !(Array.isArray(tokenVct) && tokenVct.includes(expectedVct))) {
    throw new Error("credential_type_mismatch");
  }
}

function jwkEquals(a, b) {
  if (!a || !b) return false;
  const keys = ["kty", "crv", "x", "y", "e", "n"];
  for (const k of keys) {
    if ((a[k] || undefined) !== (b[k] || undefined)) return false;
  }
  return true;
}

function base64DerToPem(b64) {
  const body = (b64 || "").replace(/\s+/g, "");
  const lines = body.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

async function resolveDidDocument(did) {
  if (did.startsWith('did:web:')) {
    // did:web:example.com:path -> https://example.com/.well-known/did.json or with path
    const withoutPrefix = did.replace(/^did:web:/, '');
    const parts = withoutPrefix.split(':');
    const host = parts.shift();
    const path = parts.length ? '/' + parts.join('/') : '';
    const urls = [
      `https://${host}/.well-known/did.json`,
      `https://${host}${path}/did.json`,
    ];
    for (const url of urls) {
      try {
        const res = await fetch(url);
        if (res.ok) return res.json();
      } catch {}
    }
    throw new Error('did:web resolution failed');
  }
  if (did.startsWith('did:jwk:')) {
    // did:jwk encodes the JWK as base64url(JSON)
    const b64 = did.substring('did:jwk:'.length);
    try {
      const json = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
      return { verificationMethod: [{ id: did + '#0', type: 'JsonWebKey2020', publicKeyJwk: json }] };
    } catch (e) {
      throw new Error('did:jwk decode failed');
    }
  }
  throw new Error('Unsupported DID method');
}

async function verifyJwsWithDid(jws, header, didOrIss) {
  const did = (header?.kid && header.kid.startsWith('did:')) ? header.kid.split('#')[0] : didOrIss;
  if (!did || !String(did).startsWith('did:')) throw new Error('No DID available for verification');
  const doc = await resolveDidDocument(String(did));
  const vms = doc.verificationMethod || [];
  let lastErr = null;
  for (const [idx, vm] of vms.entries()) {
    const jwk = vm.publicKeyJwk;
    if (!jwk) continue;
    try {
      const key = await importJWK(jwk, header?.alg || 'ES256');
      const verified = await jwtVerify(jws, key);
      return verified;
    } catch (e) {
      lastErr = e;
      // continue
    }
  }
  throw lastErr || new Error('DID verification failed');
}


