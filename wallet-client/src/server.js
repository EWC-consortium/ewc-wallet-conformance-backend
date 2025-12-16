import express from "express";
import fetch from "node-fetch";
import { createProofJwt, generateDidJwkFromPrivateJwk, ensureOrCreateEcKeyPair, createPkcePair, createWIA, createWUA, createDPoP } from "./lib/crypto.js";
import { performPresentation, resolveDeepLinkFromEndpoint } from "./lib/presentation.js";
import { storeWalletCredentialByType, walletRedisClient, appendWalletLog, getWalletLogs } from "./lib/cache.js";
import { jwtVerify, decodeJwt, decodeProtectedHeader, createLocalJWKSet, importJWK, importX509 } from "jose";
import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";
import { verifyReceivedMdlToken } from "../utils/mdlVerification.js";
import { didKeyToJwks } from "../utils/cryptoUtils.js";

const app = express();
app.use(express.json({ limit: "2mb" }));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function makeSessionLogger(sessionId) {
  return function sessionLog(...args) {
    try { console.log(...args); } catch {}
    try {
      const message = args.map((a) => {
        if (typeof a === 'string') return a;
        try { return JSON.stringify(a); } catch { return String(a); }
      }).join(' ');
      appendWalletLog(sessionId, { level: 'info', message }).catch(() => {});
    } catch {}
  };
}

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
    const offeredConfigurationIds = getOfferedConfigurationIds(offerConfig);
    try {
      console.log("[/issue] offer.credential_issuer=", offerConfig?.credential_issuer);
      console.log("[/issue] offer.config_ids=", offeredConfigurationIds);
      console.log("[/issue] offer.grants=", Object.keys(offerConfig?.grants || {}));
      console.log("[/issue] offer full structure:", JSON.stringify(offerConfig, null, 2));
    } catch {}
    const { grants } = offerConfig;
    const apiBase = (offerConfig.credential_issuer || issuerBase).replace(/\/$/, "");
    const issuerMeta = await discoverIssuerMetadata(apiBase);
    try {
      console.log("[/issue] issuerMeta.token_endpoint=", issuerMeta?.token_endpoint);
      console.log("[/issue] issuerMeta.credential_endpoint=", issuerMeta?.credential_endpoint);
      console.log("[/issue] issuerMeta.nonce_endpoint=", issuerMeta?.nonce_endpoint);
      const cfgKeys = Object.keys(issuerMeta?.credential_configurations_supported || {});
      console.log("[/issue] issuerMeta.credential_configurations_supported keys=", cfgKeys.slice(0, 5), cfgKeys.length > 5 ? `(+${cfgKeys.length - 5} more)` : "");
    } catch {}
    const configurationId = pickConfigurationId(offerConfig, req.body.credential);
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
      authorizationServer: preAuthGrant.authorization_server, // Optional grant-level AS identifier
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

// GET /logs/:sessionId
// Returns all logs stored for a session from Redis
app.get("/logs/:sessionId", async (req, res) => {
  try {
    const { sessionId } = req.params;
    if (!sessionId) {
      return res.status(400).json({ error: "invalid_request", error_description: "sessionId is required" });
    }
    const logs = await getWalletLogs(sessionId);
    if (!logs) {
      return res.status(404).json({ error: "not_found", error_description: "No logs for session" });
    }
    return res.json({ sessionId, logs });
  } catch (e) {
    console.error("[logs] error:", e);
    return res.status(500).json({ error: "server_error", error_description: e.message || String(e) });
  }
});

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

  const sessionLog = makeSessionLogger(sessionId);

  await setStatus("pending");

  try {
    // VP request
    if (/^openid4vp:\/\//.test(deepLink)) {
      const verifierBase = (req.body.verifier || "http://localhost:3000").replace(/\/$/, "");
      const result = await performPresentation({ deepLink, verifierBase, credentialType: req.body.credential, keyPath: req.body.keyPath }, sessionId);
      const okPayload = await setStatus("ok", { result: result || { status: "ok" } });
      return res.json(okPayload);
    }

    // VCI request (credential offer)
    if (/^(openid-credential-offer:\/\/|haip:\/\/)/.test(deepLink)) {
      const issuerBaseDefault = (req.body.issuer || "http://localhost:3000").replace(/\/$/, "");
      sessionLog("[/session] VCI deepLink:", deepLink);
      const offerCfg = await resolveOfferConfig(deepLink, sessionId);
      const offeredConfigurationIds = getOfferedConfigurationIds(offerCfg);
      const { grants } = offerCfg;
      const apiBase = (offerCfg.credential_issuer || issuerBaseDefault).replace(/\/$/, "");
      const issuerMeta = await discoverIssuerMetadata(apiBase, sessionId);
      try {
        sessionLog("[/session] offer.credential_issuer=", offerCfg?.credential_issuer);
        sessionLog("[/session] offer.config_ids=", offeredConfigurationIds);
        sessionLog("[/session] offer.grants=", Object.keys(grants || {}));
        sessionLog("[/session] offer full structure:", JSON.stringify(offerCfg, null, 2));
        sessionLog("[/session] issuerMeta.token_endpoint=", issuerMeta?.token_endpoint);
        sessionLog("[/session] issuerMeta.credential_endpoint=", issuerMeta?.credential_endpoint);
        sessionLog("[/session] issuerMeta.nonce_endpoint=", issuerMeta?.nonce_endpoint);
        const cfgKeys = Object.keys(issuerMeta?.credential_configurations_supported || {});
        sessionLog("[/session] issuerMeta.credential_configurations_supported keys=", cfgKeys.slice(0, 5), cfgKeys.length > 5 ? `(+${cfgKeys.length - 5} more)` : "");
      } catch {}
      const configurationId = pickConfigurationId(offerCfg, req.body.credential);
      if (!configurationId) {
        console.warn("[/session] no credential_configuration_id available in offer or request. Aborting.");
        const failed = await setStatus("failed", { error: "No credential_configuration_id available" });
        return res.status(400).json({ error: "invalid_request", error_description: "No credential_configuration_id available", state: failed });
      }

      // Pre-authorized code flow
      if (grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"]) {
        try {
          const preAuthGrant = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]; 
          sessionLog("[/session] invoking pre-authorized issuance. configurationId=", configurationId);
          
          const result = await runPreAuthorizedIssuance({
            apiBase,
            issuerMeta,
            configurationId,
            preAuthorizedCode: preAuthGrant["pre-authorized_code"],
            txCodeConfig: preAuthGrant.tx_code, // Pass original config
            authorizationServer: preAuthGrant.authorization_server, // Optional grant-level AS identifier
            keyPath: req.body.keyPath,
            pollTimeoutMs: req.body.pollTimeoutMs,
            pollIntervalMs: req.body.pollIntervalMs,
            userPin: pin, // Pass the pin directly
          }, sessionId);
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
          sessionLog("[/session] invoking authorization code issuance. configurationId=", configurationId);
          const result = await runAuthorizationCodeIssuance({
            apiBase,
            issuerMeta,
            configurationId,
            issuerState: authGrant.issuer_state,
            authorizationServer: authGrant.authorization_server, // Optional grant-level AS identifier
            keyPath: req.body.keyPath,
            pollTimeoutMs: req.body.pollTimeoutMs,
            pollIntervalMs: req.body.pollIntervalMs,
          }, sessionId);
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
    const offeredConfigurationIds = getOfferedConfigurationIds(offerCfg);
    try {
      console.log("[/issue-codeflow] offer.credential_issuer=", offerCfg?.credential_issuer);
      console.log("[/issue-codeflow] offer.config_ids=", offeredConfigurationIds);
      console.log("[/issue-codeflow] offer.grants=", Object.keys(offerCfg?.grants || {}));
      console.log("[/issue-codeflow] offer full structure:", JSON.stringify(offerCfg, null, 2));
    } catch {}
    const { grants } = offerCfg;
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

    const configurationId = pickConfigurationId(offerCfg, req.body.credential);
    if (!configurationId) return res.status(400).json({ error: "invalid_request", error_description: "No credential_configuration_id available" });

    const result = await runAuthorizationCodeIssuance({
      apiBase,
      issuerMeta,
      configurationId,
      issuerState: authGrant.issuer_state,
      authorizationServer: authGrant.authorization_server, // Optional grant-level AS identifier
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

async function resolveOfferConfig(deepLink, logSessionId) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
  const url = new URL(deepLink.replace(/^haip:\/\//, "openid-credential-offer://"));
  if (url.protocol !== "openid-credential-offer:") throw new Error("Unsupported offer scheme");
  const inlineOffer = url.searchParams.get("credential_offer");
  if (inlineOffer) {
    const parsed = parseCredentialOfferParam(inlineOffer);
    try { slog("[offer] parsed inline offer", { hasCredentialIssuer: !!parsed?.credential_issuer, cfgCount: getOfferedConfigurationIds(parsed).length }); } catch {}
    return parsed;
  }

  const encoded = url.searchParams.get("credential_offer_uri");
  if (!encoded) throw new Error("Missing credential_offer_uri in offer");
  const offerUri = decodeURIComponent(encoded);
  console.log("[offer] fetching credential_offer_uri:", offerUri); try { slog("[offer] fetching offer", { offerUri }); } catch {}
  const res = await fetch(offerUri);
  console.log("[offer] credential_offer_uri status:", res.status); try { slog("[offer] offer status", { status: res.status }); } catch {}
  if (!res.ok) throw new Error(`Offer-config error ${res.status}`);
  const json = await res.json();
  try { slog("[offer] offer fetched", { hasCredentialIssuer: !!json?.credential_issuer, cfgCount: getOfferedConfigurationIds(json).length }); } catch {}
  return json;
}

function parseCredentialOfferParam(value) {
  const attempts = new Set([value]);
  try {
    attempts.add(decodeURIComponent(value));
  } catch {
    // ignore decode errors
  }

  for (const attempt of attempts) {
    try {
      return JSON.parse(attempt);
    } catch {
      try {
        const decoded = Buffer.from(attempt, "base64url").toString("utf8");
        return JSON.parse(decoded);
      } catch {
        // continue
      }
    }
  }

  throw new Error("Unable to parse credential_offer parameter");
}

function getOfferedConfigurationIds(offer) {
  if (!offer || typeof offer !== "object") return [];
  const ids = Array.isArray(offer.credential_configuration_ids) ? offer.credential_configuration_ids : [];
  if (ids.length > 0) return ids;
  const legacy = offer.credentials;
  if (Array.isArray(legacy)) return legacy;
  if (legacy && typeof legacy === "object") return Object.keys(legacy);
  return [];
}

function pickConfigurationId(offer, requestedId) {
  if (requestedId) return requestedId;
  const ids = getOfferedConfigurationIds(offer);
  return ids.length > 0 ? ids[0] : undefined;
}

async function discoverIssuerMetadata(credentialIssuerBase, logSessionId) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
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
  console.log("[issuer-meta] trying candidates:", candidates); try { slog("[issuer-meta] candidates", { candidates }); } catch {}
  for (const url of candidates) {
    try {
      const res = await fetch(url);
      console.log("[issuer-meta]", url, "->", res.status); try { slog("[issuer-meta] fetch", { url, status: res.status }); } catch {}
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
    slog("[issuer-meta] summary", { token: !!meta?.token_endpoint, credential: !!meta?.credential_endpoint, nonce: !!meta?.nonce_endpoint, deferred: !!meta?.credential_deferred_endpoint, authz: !!meta?.authorization_server });
  } catch {}
  return meta;
}

async function discoverAuthorizationServerMetadata(authorizationServerBase, logSessionId) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
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
  console.log("[as-meta] trying candidates:", candidates); try { slog("[as-meta] candidates", { candidates }); } catch {}
  for (const url of candidates) {
    try {
      const res = await fetch(url);
      console.log("[as-meta]", url, "->", res.status); try { slog("[as-meta] fetch", { url, status: res.status }); } catch {}
      if (res.ok) { 
        console.log("[as-meta] selected:", url); 
        let meta;
        try {
          meta = await res.json();
        } catch (e) {
          lastErr = "invalid_json: " + (e?.message || String(e));
          continue;
        }
        try {
          validateAuthorizationServerMetadata(meta);
        } catch (e) {
          console.error("[as-meta] metadata validation failed:", e?.message || e);
          try { slog("[as-meta] validation_failed", { error: e?.message || String(e), meta }); } catch {}
          lastErr = e?.message || String(e);
          continue;
        }
        try { slog("[as-meta] selected", { url }); } catch {}
        return meta; 
      }
      lastErr = res.status;
    } catch (e) {
      lastErr = e.message || String(e);
    }
  }
  try { slog("[as-meta] failed", { lastErr }); } catch {}
  throw new Error(`AS metadata fetch error ${lastErr}`);
}

/**
 * Basic HAIP-aligned sanity checks on the Authorization Server metadata.
 * This is intentionally strict so the wallet-client will catch regressions
 * similar to the ones that broke interoperability with the EUDI Wallet.
 */
function validateAuthorizationServerMetadata(meta) {
  if (!meta || typeof meta !== "object") {
    throw new Error("invalid_as_metadata: metadata must be a JSON object");
  }

  // token_endpoint is mandatory for any usable AS
  if (!meta.token_endpoint || typeof meta.token_endpoint !== "string") {
    throw new Error("invalid_as_metadata: missing required 'token_endpoint'");
  }

  const methods = meta.token_endpoint_auth_methods_supported;
  if (!Array.isArray(methods) || methods.length === 0) {
    throw new Error("invalid_as_metadata: 'token_endpoint_auth_methods_supported' must be a non-empty array");
  }

  // For our HAIP / EUDI interoperability we rely on the AS supporting BOTH:
  // - "public"                  : for non-attested / dev wallets
  // - "attest_jwt_client_auth"  : for HAIP-compliant attested wallets
  const requiredMethods = ["public", "attest_jwt_client_auth"];
  for (const m of requiredMethods) {
    if (!methods.includes(m)) {
      throw new Error(
        `invalid_as_metadata: 'token_endpoint_auth_methods_supported' must include '${m}' (found: ${JSON.stringify(methods)})`
      );
    }
  }

  // Ensure basic client attestation algorithm advertising is present and supports ES256,
  // matching what the EUDI reference issuer exposes.
  const attestationAlgs = meta.client_attestation_signing_alg_values_supported;
  const attestationPopAlgs = meta.client_attestation_pop_signing_alg_values_supported;
  if (!Array.isArray(attestationAlgs) || !attestationAlgs.includes("ES256")) {
    throw new Error(
      "invalid_as_metadata: 'client_attestation_signing_alg_values_supported' must include 'ES256'"
    );
  }
  if (!Array.isArray(attestationPopAlgs) || !attestationPopAlgs.includes("ES256")) {
    throw new Error(
      "invalid_as_metadata: 'client_attestation_pop_signing_alg_values_supported' must include 'ES256'"
    );
  }

  // We expect at least the "openid" scope to be advertised. Additional scopes are fine.
  const scopes = meta.scopes_supported;
  if (!Array.isArray(scopes) || !scopes.includes("openid")) {
    throw new Error(
      "invalid_as_metadata: 'scopes_supported' must be an array including 'openid'"
    );
  }

  // Authorization Code grant is required for code flow tests.
  const grants = meta.grant_types_supported;
  if (Array.isArray(grants) && !grants.includes("authorization_code")) {
    throw new Error(
      "invalid_as_metadata: 'grant_types_supported' must include 'authorization_code' for authorization code flows"
    );
  }
}

function makeTxCode(cfg) {
  if (cfg?.input_mode === "numeric" && typeof cfg?.length === "number") {
    return "".padStart(cfg.length, "1");
  }
  return undefined;
}

async function httpPostJson(url, body, logSessionId) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
  const start = Date.now();
  try { console.log("[http] POST JSON ->", url); } catch {}
  try { slog("[http] POST JSON", { url }); } catch {}
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) });
  const duration = Date.now() - start;
  try { console.log("[http] <-", url, res.status, duration + "ms"); } catch {}
  try { slog("[http] response", { url, status: res.status, duration }); } catch {}
  return res;
}

async function httpPostForm(url, params, logSessionId, dpopHeader = null) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
  const form = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => { if (typeof v !== 'undefined' && v !== null) form.set(k, String(v)); });
  const start = Date.now();
  try { console.log("[http] POST FORM ->", url); } catch {}
  try { slog("[http] POST FORM", { url }); } catch {}
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  if (dpopHeader) {
    headers["DPoP"] = dpopHeader;
  }
  const res = await fetch(url, { method: "POST", headers, body: form.toString() });
  const duration = Date.now() - start;
  try { console.log("[http] <-", url, res.status, duration + "ms"); } catch {}
  try { slog("[http] response", { url, status: res.status, duration }); } catch {}
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

async function runPreAuthorizedIssuance({ apiBase, issuerMeta, configurationId, preAuthorizedCode, txCodeConfig, authorizationServer, keyPath, pollTimeoutMs, pollIntervalMs, userPin }, logSessionId) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
  try { slog("[preauth] start", { configurationId, hasTxCodeCfg: !!txCodeConfig }); } catch {}
  // Draft-15: If tx_code is indicated in offer and not provided by user, do NOT fabricate. Require user input.
  let txCode = undefined;
  if (userPin) {
    txCode = userPin;
    console.log("[preauth] using provided userPin for tx_code"); try { slog("[preauth] using userPin for tx_code"); } catch {}
  } else if (txCodeConfig) {
    console.warn("[preauth] tx_code indicated in offer but no user PIN provided. Aborting per draft-15."); try { slog("[preauth] tx_code required but pin missing"); } catch {}
    throw new Error("tx_code_required: offer indicates tx_code; provide 'pin' in request body");
  }
  let tokenEndpoint = issuerMeta.token_endpoint || null;
  // If token_endpoint is not in issuer metadata, try authorization server metadata per RFC 8414
  if (!tokenEndpoint) {
    // Check for authorization_servers array in issuer metadata
    // Per OIDC4VCI v1.0: "If this parameter is omitted, the entity providing the Credential Issuer 
    // is also acting as the Authorization Server, i.e., the Credential Issuer's identifier is used 
    // to obtain the Authorization Server metadata."
    const authorizationServers = Array.isArray(issuerMeta.authorization_servers) ? issuerMeta.authorization_servers : 
                                  (issuerMeta.authorization_server ? [issuerMeta.authorization_server] : []);
    
    let asBase = null;
    
    if (authorizationServers.length > 0) {
      // authorization_servers is present - use it
      // Use grant-level authorization_server if provided (must match one in authorization_servers array)
      if (authorizationServer) {
        if (!authorizationServers.includes(authorizationServer)) {
          console.error("[preauth] grant authorization_server does not match any entry in authorization_servers array");
          try { slog("[preauth] grant authorization_server mismatch", { grantAS: authorizationServer, availableAS: authorizationServers }); } catch {}
          throw new Error("invalid_authorization_server: grant authorization_server must match one of the values in authorization_servers array");
        }
        asBase = authorizationServer;
        console.log("[preauth] using grant-level authorization_server:", asBase); 
        try { slog("[preauth] using grant-level authorization_server", { asBase }); } catch {}
      } else {
        // Use first authorization server from issuer metadata
        asBase = authorizationServers[0];
        console.log("[preauth] using first authorization_server from issuer metadata:", asBase); 
        try { slog("[preauth] using first authorization_server", { asBase }); } catch {}
      }
    } else {
      // authorization_servers is omitted - use credential_issuer identifier as Authorization Server
      // Per spec: "the Credential Issuer's identifier is used to obtain the Authorization Server metadata"
      asBase = issuerMeta.credential_issuer || apiBase;
      console.log("[preauth] authorization_servers omitted, using credential_issuer as Authorization Server:", asBase);
      try { slog("[preauth] using credential_issuer as AS", { asBase }); } catch {}
      
      // Grant-level authorization_server MUST NOT be used when authorization_servers is omitted
      if (authorizationServer) {
        console.error("[preauth] grant authorization_server MUST NOT be used when authorization_servers is omitted");
        try { slog("[preauth] grant authorization_server invalid when authorization_servers omitted"); } catch {}
        throw new Error("invalid_authorization_server: grant authorization_server MUST NOT be used when authorization_servers parameter is omitted");
      }
    }
    
    try {
      const asMeta = await discoverAuthorizationServerMetadata(asBase, logSessionId);
      tokenEndpoint = asMeta.token_endpoint;
      if (!tokenEndpoint) {
        console.error("[preauth] authorization server metadata does not contain token_endpoint");
        try { slog("[preauth] AS metadata missing token_endpoint", { asBase }); } catch {}
        throw new Error("token_endpoint_required: authorization server metadata must include 'token_endpoint'");
      }
      console.log("[preauth] tokenEndpoint discovered via AS:", tokenEndpoint); 
      try { slog("[preauth] tokenEndpoint discovered via AS", { tokenEndpoint }); } catch {}
    } catch (e) {
      console.error("[preauth] AS metadata discovery failed:", e?.message || e); 
      try { slog("[preauth] AS metadata discovery failed", { error: e?.message || String(e) }); } catch {}
      throw e; // Re-throw to fail fast instead of falling back
    }
  }
  
  // tokenEndpoint should be set at this point (either from issuer metadata or AS metadata discovery)
  // If not, AS metadata discovery should have thrown an error
  if (!tokenEndpoint) {
    console.error("[preauth] token_endpoint could not be determined");
    try { slog("[preauth] token_endpoint determination failed"); } catch {}
    throw new Error("token_endpoint_required: unable to determine token_endpoint from issuer or authorization server metadata");
  }
  
  console.log("[preauth] apiBase=", apiBase, "configurationId=", configurationId); try { slog("[preauth] apiBase", { apiBase, configurationId }); } catch {}
  console.log("[preauth] tokenEndpoint=", tokenEndpoint); try { slog("[preauth] tokenEndpoint", { tokenEndpoint }); } catch {}
  console.log("[preauth] requesting token..."); try { slog("[preauth] requesting token"); } catch {}
  
  // Generate DPoP (Demonstrating Proof-of-Possession) for token request
  let dpopJwt = null;
  try {
    const { privateJwk: dpopPrivateJwk, publicJwk: dpopPublicJwk } = await ensureOrCreateEcKeyPair(keyPath, "ES256");
    dpopJwt = await createDPoP({
      privateJwk: dpopPrivateJwk,
      publicJwk: dpopPublicJwk,
      htu: tokenEndpoint,
      htm: "POST",
      alg: "ES256"
    });
    console.log("[preauth] DPoP generated for token request"); try { slog("[preauth] DPoP generated", { hasDPoP: !!dpopJwt }); } catch {}
  } catch (dpopError) {
    console.warn("[preauth] Failed to generate DPoP:", dpopError?.message); try { slog("[preauth] DPoP generation failed", { error: dpopError?.message }); } catch {}
  }
  
  // Generate WIA (Wallet Instance Attestation) for token request
  let wiaJwt = null;
  try {
    const { privateJwk: wiaPrivateJwk, publicJwk: wiaPublicJwk } = await ensureOrCreateEcKeyPair(keyPath, "ES256");
    const wiaIssuer = generateDidJwkFromPrivateJwk(wiaPublicJwk);
    wiaJwt = await createWIA({
      privateJwk: wiaPrivateJwk,
      publicJwk: wiaPublicJwk,
      issuer: wiaIssuer,
      audience: tokenEndpoint,
      alg: "ES256",
      ttlHours: 1
    });
    console.log("[preauth] WIA generated for token request"); try { slog("[preauth] WIA generated", { hasWIA: !!wiaJwt }); } catch {}
  } catch (wiaError) {
    console.warn("[preauth] Failed to generate WIA:", wiaError?.message); try { slog("[preauth] WIA generation failed", { error: wiaError?.message }); } catch {}
  }
  
  const tokenAuthzDetails = [
    {
      type: "openid_credential",
      credential_configuration_id: configurationId,
      ...(issuerMeta?.credential_issuer ? { locations: [issuerMeta.credential_issuer] } : {}),
    },
  ];
  const tokenPayload = {
    grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": preAuthorizedCode,
    ...(txCode ? { tx_code: txCode } : {}),
    authorization_details: JSON.stringify(tokenAuthzDetails),
    ...(wiaJwt ? { client_assertion: wiaJwt, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" } : {}),
  };
  const tokenRes = await httpPostForm(tokenEndpoint, tokenPayload, logSessionId, dpopJwt);
  console.log("[preauth] tokenRes.status=", tokenRes.status); 
  try { slog("[preauth] tokenRes.status", { status: tokenRes.status }); } catch {}
  console.log("[preauth] tokenRes.headers:", Object.fromEntries(tokenRes.headers.entries())); 
  try { slog("[preauth] tokenRes.headers", { headers: Object.fromEntries(tokenRes.headers.entries()) }); } catch {}
  
  const tokenResponseText = await tokenRes.text().catch(() => "");
  console.log("[preauth] tokenRes.body length:", tokenResponseText.length); 
  try { slog("[preauth] tokenRes.body", { length: tokenResponseText.length }); } catch {}
  
  if (!tokenRes.ok) {
    console.error("[preauth] token error", tokenRes.status, tokenResponseText?.slice(0, 500));
    let err = {};
    try { err = JSON.parse(tokenResponseText); } catch {}
    console.error("[preauth] token error parsed:", JSON.stringify(err, null, 2)); 
    try { slog("[preauth] token error", { status: tokenRes.status, err, body: tokenResponseText?.slice(0, 500) }); } catch {}
    throw new Error(`token_error ${tokenRes.status}: ${JSON.stringify(err)}`);
  }
  
  let tokenBody;
  try {
    tokenBody = JSON.parse(tokenResponseText);
    console.log("[preauth] token response parsed successfully"); 
    try { slog("[preauth] token response parsed", { hasAccessToken: !!tokenBody.access_token, hasCNonce: !!tokenBody.c_nonce }); } catch {}
  } catch (e) {
    console.error("[preauth] failed to parse token response as JSON:", e?.message); 
    try { slog("[preauth] token response parse failed", { error: e?.message, body: tokenResponseText?.slice(0, 500) }); } catch {}
    throw new Error(`token_error: invalid JSON response - ${e?.message}`);
  }
  const accessToken = tokenBody.access_token;
  let c_nonce = tokenBody.c_nonce;
  let c_nonce_expires_in = tokenBody.c_nonce_expires_in;
  console.log("[preauth] got access_token=", accessToken ? "yes" : "no", "c_nonce=", c_nonce ? "yes" : "no"); try { slog("[preauth] token received", { hasAccessToken: !!accessToken, hasCNonce: !!c_nonce }); } catch {}
  if (!c_nonce && issuerMeta.nonce_endpoint) {
    const nonceEndpoint = issuerMeta.nonce_endpoint;
    console.log("[preauth] nonceEndpoint=", nonceEndpoint); try { slog("[preauth] nonceEndpoint", { nonceEndpoint }); } catch {}
    const nonceRes = await httpPostJson(nonceEndpoint, {}, logSessionId); try { slog("[preauth] nonce request", { endpoint: nonceEndpoint, status: nonceRes.status }); } catch {}
    if (!nonceRes.ok) {
      const text = await nonceRes.text().catch(() => "");
      console.error("[preauth] nonce error", nonceRes.status, text?.slice(0, 500));
      let err = {};
      try { err = JSON.parse(text); } catch {}
      try { slog("[preauth] nonce error", { status: nonceRes.status, err }); } catch {}
      throw new Error(`nonce_error ${nonceRes.status}: ${JSON.stringify(err)}`);
    }
    const nonceJson = await nonceRes.json();
    c_nonce = nonceJson.c_nonce;
    c_nonce_expires_in = nonceJson.c_nonce_expires_in;
    console.log("[preauth] obtained c_nonce from nonce endpoint"); try { slog("[preauth] obtained c_nonce from nonce endpoint", { hasExpiresIn: !!c_nonce_expires_in }); } catch {}
  } else if (!c_nonce) {
    console.warn("[preauth] no nonce endpoint and no c_nonce from token; proceeding without nonce (may be rejected)"); try { slog("[preauth] no c_nonce available"); } catch {}
  }

  // Algorithm negotiation
  const supportedAlgs = issuerMeta?.proof_types_supported?.jwt?.proof_signing_alg_values_supported || issuerMeta?.credential_configurations_supported?.[configurationId]?.proof_types_supported?.jwt?.proof_signing_alg_values_supported || [];
  const preferredOrder = ["ES256", "ES384", "ES512", "EdDSA"];
  const selectedAlg = (Array.isArray(supportedAlgs) && supportedAlgs.length)
    ? (preferredOrder.find((a) => supportedAlgs.includes(a)) || supportedAlgs[0])
    : "ES256";
  console.log("[preauth] issuer supported proof algs:", supportedAlgs); try { slog("[preauth] supported algs", { supportedAlgs }); } catch {}
  console.log("[preauth] selected proof alg:", selectedAlg); try { slog("[preauth] selected alg", { selectedAlg }); } catch {}

  const aud = issuerMeta?.credential_issuer || apiBase;
  console.log("[preauth] proof audience:", aud, issuerMeta?.credential_issuer ? "(from issuerMeta.credential_issuer)" : "(fallback apiBase)"); try { slog("[preauth] proof audience", { aud }); } catch {}
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath, selectedAlg);
  const didJwk = generateDidJwkFromPrivateJwk(publicJwk);

  const credentialEndpoint = issuerMeta.credential_endpoint || `${apiBase}/credential`;
  
  // Generate WUA (Wallet Unit Attestation) for credential request
  let wuaJwt = null;
  try {
    const { privateJwk: wuaPrivateJwk, publicJwk: wuaPublicJwk } = await ensureOrCreateEcKeyPair(keyPath, "ES256");
    const wuaIssuer = generateDidJwkFromPrivateJwk(wuaPublicJwk);
    
    // Create WUA with required claims
    wuaJwt = await createWUA({
      privateJwk: wuaPrivateJwk,
      publicJwk: wuaPublicJwk,
      issuer: wuaIssuer,
      audience: credentialEndpoint,
      attestedKeys: [publicJwk], // Attest the key used for proof
      eudiWalletInfo: {
        general_info: {
          name: "Test Wallet Client",
          version: "1.0.0"
        },
        key_storage_info: {
          storage_type: "software",
          protection_level: "software"
        }
      },
      alg: "ES256",
      ttlHours: 24
    });
    console.log("[preauth] WUA generated for credential request"); try { slog("[preauth] WUA generated", { hasWUA: !!wuaJwt }); } catch {}
  } catch (wuaError) {
    console.warn("[preauth] Failed to generate WUA:", wuaError?.message); try { slog("[preauth] WUA generation failed", { error: wuaError?.message }); } catch {}
  }
  
  // Include WUA in the proof JWT header as key_attestation (per spec)
  const proofJwt = await createProofJwt({ 
    privateJwk, 
    publicJwk, 
    audience: aud, 
    nonce: c_nonce, 
    issuer: didJwk, 
    typ: "openid4vci-proof+jwt", 
    alg: selectedAlg,
    key_attestation: wuaJwt || undefined
  });
  try { console.log("[preauth] proof JWT created. len=", proofJwt?.length || 0); slog("[preauth] proof created", { length: proofJwt?.length || 0 }); } catch {}
  
  console.log("[preauth] credentialEndpoint=", credentialEndpoint); try { slog("[preauth] credentialEndpoint", { credentialEndpoint }); } catch {}
  console.log("[preauth] requesting credential..."); try { slog("[preauth] requesting credential"); } catch {}
  const credReq = { 
    credential_configuration_id: configurationId, 
    proofs: { 
      jwt: [proofJwt]
    } 
  };
  console.log("[preauth] credential request:", JSON.stringify({ ...credReq, proofs: { jwt: ["<redacted>"] } }, null, 2)); try { slog("[preauth] credential request body", { hasBody: true }); } catch {}
  if (accessToken) {
    console.log("[preauth] access_token preview:", `${accessToken.substring(0, 20)}...`); try { slog("[preauth] access_token preview", { preview: `${accessToken.substring(0, 20)}...` }); } catch {}
  } else {
    console.warn("[preauth] access_token missing in token response"); try { slog("[preauth] access_token missing"); } catch {}
  }
  try { slog("[preauth] credential request", { configurationId, hasProof: !!proofJwt }); } catch {}
  
  const credRes = await fetch(credentialEndpoint, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
    body: JSON.stringify(credReq),
  });
  console.log("[preauth] credentialRes.status=", credRes.status); 
  try { slog("[preauth] credentialRes.status", { status: credRes.status }); } catch {}
  console.log("[preauth] credentialRes.headers:", Object.fromEntries(credRes.headers.entries())); 
  try { slog("[preauth] credentialRes.headers", { headers: Object.fromEntries(credRes.headers.entries()) }); } catch {}

  const responseText = await credRes.text().catch(() => "");
  console.log("[preauth] credentialRes.body length:", responseText.length); 
  try { slog("[preauth] credentialRes.body", { length: responseText.length }); } catch {}

  if (!credRes.ok) {
    console.error("[preauth] credential error", credRes.status); 
    try { slog("[preauth] credential error start", { status: credRes.status }); } catch {}
    console.error("[preauth] credential error response headers:", Object.fromEntries(credRes.headers.entries()));
    console.error("[preauth] credential error response body:", responseText);
    
    let err = {};
    try { 
      err = JSON.parse(responseText); 
      console.error("[preauth] credential error parsed JSON:", JSON.stringify(err, null, 2)); 
      try { slog("[preauth] credential error parsed", { err }); } catch {}
    } catch (parseErr) {
      console.error("[preauth] credential error response is not JSON, raw text:", responseText); 
      try { slog("[preauth] credential error not JSON", { text: responseText?.slice(0, 500) }); } catch {}
      err = { error: "invalid_response", error_description: responseText?.slice(0, 500) };
    }
    
    try { slog("[preauth] credential error", { status: credRes.status, err }); } catch {}
    throw new Error(`credential_error ${credRes.status}: ${JSON.stringify(err)}`);
  }

  // Log successful response body (may be large, so log preview)
  try {
    const responsePreview = responseText.length > 1000 ? responseText.substring(0, 1000) + "..." : responseText;
    console.log("[preauth] credential response preview:", responsePreview); 
    try { slog("[preauth] credential response preview", { length: responseText.length, preview: responsePreview }); } catch {}
  } catch (e) {
    console.warn("[preauth] failed to log credential response:", e?.message); 
    try { slog("[preauth] failed to log response", { error: e?.message }); } catch {}
  }

  if (credRes.status === 202) {
    let credBody;
    try {
      credBody = JSON.parse(responseText);
    } catch (e) {
      console.error("[preauth] failed to parse deferred response as JSON:", e?.message); 
      try { slog("[preauth] deferred response parse failed", { error: e?.message, body: responseText?.slice(0, 500) }); } catch {}
      throw new Error(`credential_error ${credRes.status}: invalid JSON response`);
    }
    const { transaction_id } = credBody;
    console.log("[preauth] deferred issuance, transaction_id:", transaction_id); 
    try { slog("[preauth] deferred issuance", { transaction_id }); } catch {}
    const start = Date.now();
    const timeout = pollTimeoutMs ?? 30000;
    const interval = pollIntervalMs ?? 2000;
    const deferredEndpoint = issuerMeta.credential_deferred_endpoint || `${apiBase}/credential_deferred`;
    while (Date.now() - start < timeout) {
      await sleep(interval);
      const defRes = await httpPostJson(deferredEndpoint, { transaction_id }, logSessionId);
      console.log("[preauth] deferred poll ->", defRes.status); 
      try { slog("[preauth] deferred poll", { status: defRes.status }); } catch {}
      if (defRes.ok) {
        const defBodyText = await defRes.text().catch(() => "");
        console.log("[preauth] deferred response body length:", defBodyText.length); 
        try { slog("[preauth] deferred response", { length: defBodyText.length }); } catch {}
        let defBody;
        try {
          defBody = JSON.parse(defBodyText);
        } catch (e) {
          console.error("[preauth] failed to parse deferred credential as JSON:", e?.message); 
          try { slog("[preauth] deferred credential parse failed", { error: e?.message, body: defBodyText?.slice(0, 500) }); } catch {}
          throw new Error(`credential_error: invalid JSON in deferred credential response`);
        }
        try { slog("[preauth] deferred ready"); } catch {}
        await validateAndStoreCredential({ configurationId, credential: defBody, issuerMeta, apiBase, keyBinding: { privateJwk, publicJwk, didJwk }, metadata: { configurationId, c_nonce, c_nonce_expires_in }, authorizationServerMeta: issuerMeta._authorizationServerMeta }, logSessionId);
        return defBody;
      } else {
        const defErrorText = await defRes.text().catch(() => "");
        console.warn("[preauth] deferred poll error:", defRes.status, defErrorText?.slice(0, 500)); 
        try { slog("[preauth] deferred poll error", { status: defRes.status, error: defErrorText?.slice(0, 500) }); } catch {}
      }
    }
    try { slog("[preauth] deferred timeout"); } catch {}
    throw new Error("timeout: Deferred issuance timed out");
  }

  let credBody;
  try {
    credBody = JSON.parse(responseText);
  } catch (e) {
    console.error("[preauth] failed to parse credential response as JSON:", e?.message); 
    try { slog("[preauth] credential response parse failed", { error: e?.message, body: responseText?.slice(0, 500) }); } catch {}
    throw new Error(`credential_error: invalid JSON response - ${e?.message}`);
  }
  console.log("[preauth] credential received, starting validation"); 
  try { slog("[preauth] credential received", { hasCredential: !!credBody }); } catch {}
  
  try {
    await validateAndStoreCredential({ configurationId, credential: credBody, issuerMeta, apiBase, keyBinding: { privateJwk, publicJwk, didJwk }, metadata: { configurationId, c_nonce, c_nonce_expires_in }, authorizationServerMeta: issuerMeta._authorizationServerMeta }, logSessionId);
  } catch (validationError) {
    console.error("[preauth] credential validation failed:", validationError?.message || validationError); 
    try { slog("[preauth] credential validation failed", { error: validationError?.message || String(validationError), stack: validationError?.stack }); } catch {}
    throw validationError;
  }
  return credBody;
}

async function runAuthorizationCodeIssuance({ apiBase, issuerMeta, configurationId, issuerState, authorizationServer, keyPath, pollTimeoutMs, pollIntervalMs }, logSessionId) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
  try { slog("[codeflow] start", { configurationId }); } catch {}
  // Discover authorization server metadata to enable PAR when available
  let authorizeEndpoint = issuerMeta.authorization_endpoint || null;
  let tokenEndpointFromAS = null;
  let parEndpoint = null;
  
  // Check for authorization_servers array in issuer metadata
  // Per OIDC4VCI v1.0: "If this parameter is omitted, the entity providing the Credential Issuer 
  // is also acting as the Authorization Server, i.e., the Credential Issuer's identifier is used 
  // to obtain the Authorization Server metadata."
  const authorizationServers = Array.isArray(issuerMeta.authorization_servers) ? issuerMeta.authorization_servers : 
                                (issuerMeta.authorization_server ? [issuerMeta.authorization_server] : []);
  
  let asBase = null;
  
  if (authorizationServers.length > 0) {
    // authorization_servers is present - use it
    // Use grant-level authorization_server if provided (must match one in authorization_servers array)
    if (authorizationServer) {
      if (!authorizationServers.includes(authorizationServer)) {
        console.error("[codeflow] grant authorization_server does not match any entry in authorization_servers array");
        try { slog("[codeflow] grant authorization_server mismatch", { grantAS: authorizationServer, availableAS: authorizationServers }); } catch {}
        throw new Error("invalid_authorization_server: grant authorization_server must match one of the values in authorization_servers array");
      }
      asBase = authorizationServer;
      console.log("[codeflow] using grant-level authorization_server:", asBase); 
      try { slog("[codeflow] using grant-level authorization_server", { asBase }); } catch {}
    } else {
      // Use first authorization server from issuer metadata
      asBase = authorizationServers[0];
      console.log("[codeflow] using first authorization_server from issuer metadata:", asBase); 
      try { slog("[codeflow] using first authorization_server", { asBase }); } catch {}
    }
  } else {
    // authorization_servers is omitted - use credential_issuer identifier as Authorization Server
    // Per spec: "the Credential Issuer's identifier is used to obtain the Authorization Server metadata"
    asBase = issuerMeta.credential_issuer || apiBase;
    console.log("[codeflow] authorization_servers omitted, using credential_issuer as Authorization Server:", asBase);
    try { slog("[codeflow] using credential_issuer as AS", { asBase }); } catch {}
    
    // Grant-level authorization_server MUST NOT be used when authorization_servers is omitted
    if (authorizationServer) {
      console.error("[codeflow] grant authorization_server MUST NOT be used when authorization_servers is omitted");
      try { slog("[codeflow] grant authorization_server invalid when authorization_servers omitted"); } catch {}
      throw new Error("invalid_authorization_server: grant authorization_server MUST NOT be used when authorization_servers parameter is omitted");
    }
  }
  
  try {
    const asMeta = await discoverAuthorizationServerMetadata(asBase, logSessionId);
    authorizeEndpoint = authorizeEndpoint || asMeta.authorization_endpoint;
    tokenEndpointFromAS = asMeta.token_endpoint || null;
    parEndpoint = asMeta.pushed_authorization_request_endpoint || null;
    if (!tokenEndpointFromAS) {
      console.error("[codeflow] authorization server metadata does not contain token_endpoint");
      try { slog("[codeflow] AS metadata missing token_endpoint", { asBase }); } catch {}
      throw new Error("token_endpoint_required: authorization server metadata must include 'token_endpoint'");
    }
    try { console.log("[codeflow] AS meta: authorize=", asMeta.authorization_endpoint, "token=", asMeta.token_endpoint, "par=", parEndpoint); slog("[codeflow] AS meta", { authorize: asMeta.authorization_endpoint, token: asMeta.token_endpoint, par: parEndpoint }); } catch {}
    // Store AS metadata for credential signature verification
    issuerMeta._authorizationServerMeta = asMeta;
  } catch (e) {
    console.error("[codeflow] AS metadata discovery failed:", e?.message || e); 
    try { slog("[codeflow] AS metadata discovery failed", { error: e?.message || String(e) }); } catch {}
    throw e; // Re-throw to fail fast instead of silently continuing
  }
  const authorizeUrl = new URL((authorizeEndpoint || apiBase + "/authorize"));
  const { codeVerifier, codeChallenge, codeChallengeMethod } = createPkcePair();
  const state = randomState();
  const redirectUri = "openid4vp://";

  // Build common authorization request parameters
  const authzDetails = [
    {
      type: "openid_credential",
      credential_configuration_id: configurationId,
      ...(issuerMeta?.credential_issuer ? { locations: [issuerMeta.credential_issuer] } : {}),
    },
  ];
  const authzParams = {
    response_type: "code",
    issuer_state: issuerState,
    state,
    client_id: "wallet-client",
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    scope: configurationId,
    authorization_details: JSON.stringify(authzDetails),
  };

  // Prefer PAR when endpoint available; fallback to direct GET otherwise
  let finalAuthorizeUrl = authorizeUrl.toString();
  if (parEndpoint) {
    try {
      // Generate WIA (Wallet Instance Attestation) for PAR request
      let parWiaJwt = null;
      try {
        const { privateJwk: parWiaPrivateJwk, publicJwk: parWiaPublicJwk } = await ensureOrCreateEcKeyPair(keyPath, "ES256");
        const parWiaIssuer = generateDidJwkFromPrivateJwk(parWiaPublicJwk);
        parWiaJwt = await createWIA({
          privateJwk: parWiaPrivateJwk,
          publicJwk: parWiaPublicJwk,
          issuer: parWiaIssuer,
          audience: parEndpoint,
          alg: "ES256",
          ttlHours: 1
        });
        console.log("[codeflow][par] WIA generated for PAR request"); try { slog("[codeflow][par] WIA generated", { hasWIA: !!parWiaJwt }); } catch {}
      } catch (parWiaError) {
        console.warn("[codeflow][par] Failed to generate WIA:", parWiaError?.message); try { slog("[codeflow][par] WIA generation failed", { error: parWiaError?.message }); } catch {}
      }
      
      const parParams = {
        ...authzParams,
        ...(parWiaJwt ? { client_assertion: parWiaJwt, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" } : {})
      };
      const parRes = await httpPostForm(parEndpoint, parParams, logSessionId);
      console.log("[codeflow][par] endpoint=", parEndpoint, "status=", parRes.status); try { slog("[codeflow][par] endpoint", { endpoint: parEndpoint, status: parRes.status }); } catch {}
      if (parRes.ok) {
        const parBody = await parRes.json().catch(() => ({}));
        const requestUri = parBody.request_uri;
        console.log("[codeflow][par] request_uri=", requestUri, "expires_in=", parBody.expires_in); try { slog("[codeflow][par] request_uri", { requestUri, expiresIn: parBody.expires_in }); } catch {}
        if (requestUri) {
          const url = new URL((authorizeEndpoint || apiBase + "/authorize"));
          url.searchParams.set("client_id", authzParams.client_id);
          url.searchParams.set("request_uri", requestUri);
          finalAuthorizeUrl = url.toString();
        }
      } else {
        const text = await parRes.text().catch(() => "");
        console.warn("[codeflow][par] failed status=", parRes.status, "body:", text?.slice(0, 300)); try { slog("[codeflow][par] failed", { status: parRes.status, body: text?.slice(0, 300) }); } catch {}
      }
    } catch (e) {
      console.warn("[codeflow][par] error:", e?.message || e); try { slog("[codeflow][par] error", { error: e?.message || String(e) }); } catch {}
    }
  }

  if (finalAuthorizeUrl === authorizeUrl.toString()) {
    // No PAR or PAR failed; append params to authorization URL directly
    Object.entries(authzParams).forEach(([k, v]) => authorizeUrl.searchParams.set(k, v));
    finalAuthorizeUrl = authorizeUrl.toString();
  }

  console.log("[codeflow] authorizeUrl:", finalAuthorizeUrl); try { slog("[codeflow] authorizeUrl", { url: finalAuthorizeUrl }); } catch {}
  const authRes = await fetch(finalAuthorizeUrl, { redirect: "manual" });
  console.log("[codeflow] authRes.status:", authRes.status); try { slog("[codeflow] authRes.status", { status: authRes.status }); } catch {}
  console.log("[codeflow] authRes.headers:", Object.fromEntries(authRes.headers.entries())); try { slog("[codeflow] authRes.headers", { headers: Object.fromEntries(authRes.headers.entries()) }); } catch {}
  
  let redirectUrl = authRes.headers.get("location");
  console.log("[codeflow] redirectUrl from headers:", redirectUrl); try { slog("[codeflow] redirectUrl from headers", { url: redirectUrl }); } catch {}
  
  if (!redirectUrl) {
    const bodyText = await authRes.text().catch(() => "");
    console.log("[codeflow] authRes body:", bodyText); try { slog("[codeflow] authRes body", { body: bodyText?.slice(0, 200) }); } catch {}
    const redirectPayload = safeParseJson(bodyText);
    console.log("[codeflow] parsed redirect payload:", redirectPayload); try { slog("[codeflow] parsed redirect payload", { payload: redirectPayload }); } catch {}
    if (redirectPayload?.redirect_uri) redirectUrl = redirectPayload.redirect_uri;
    else if (/^openid4vp:\/\//.test(bodyText)) redirectUrl = bodyText;
  }
  
  if (!redirectUrl) {
    console.error("[codeflow] No redirect URL found. Status:", authRes.status); try { slog("[codeflow] no redirect URL found", { status: authRes.status }); } catch {}
    throw new Error(`authorize_error ${authRes.status}: No redirect URL found`);
  }
  console.log("[codeflow] redirectUrl:", redirectUrl); try { slog("[codeflow] redirectUrl", { url: redirectUrl }); } catch {}
  const redirect = new URL(redirectUrl);
  const code = redirect.searchParams.get("code");
  if (!code) throw new Error("invalid_response: Authorization code missing");

  let tokenEndpoint = issuerMeta.token_endpoint || tokenEndpointFromAS || null;
  
  if (!tokenEndpoint) {
    // This should not happen if AS metadata discovery succeeded, but handle it anyway
    console.error("[codeflow] token_endpoint could not be determined from authorization server metadata");
    try { slog("[codeflow] token_endpoint determination failed", { hasAuthorizationServers: authorizationServers.length > 0 }); } catch {}
    throw new Error("token_endpoint_required: unable to determine token_endpoint from authorization server metadata");
  }
  
  console.log("[codeflow] apiBase=", apiBase, "configurationId=", configurationId); try { slog("[codeflow] apiBase", { apiBase, configurationId }); } catch {}
  console.log("[codeflow] tokenEndpoint=", tokenEndpoint); try { slog("[codeflow] tokenEndpoint", { tokenEndpoint }); } catch {}
  console.log("[codeflow] requesting token..."); try { slog("[codeflow] requesting token"); } catch {}
  
  // Generate DPoP (Demonstrating Proof-of-Possession) for token request
  let dpopJwt = null;
  try {
    const { privateJwk: dpopPrivateJwk, publicJwk: dpopPublicJwk } = await ensureOrCreateEcKeyPair(keyPath, "ES256");
    dpopJwt = await createDPoP({
      privateJwk: dpopPrivateJwk,
      publicJwk: dpopPublicJwk,
      htu: tokenEndpoint,
      htm: "POST",
      alg: "ES256"
    });
    console.log("[codeflow] DPoP generated for token request"); try { slog("[codeflow] DPoP generated", { hasDPoP: !!dpopJwt }); } catch {}
  } catch (dpopError) {
    console.warn("[codeflow] Failed to generate DPoP:", dpopError?.message); try { slog("[codeflow] DPoP generation failed", { error: dpopError?.message }); } catch {}
  }
  
  // Generate WIA (Wallet Instance Attestation) for token request
  let wiaJwt = null;
  try {
    const { privateJwk: wiaPrivateJwk, publicJwk: wiaPublicJwk } = await ensureOrCreateEcKeyPair(keyPath, "ES256");
    const wiaIssuer = generateDidJwkFromPrivateJwk(wiaPublicJwk);
    wiaJwt = await createWIA({
      privateJwk: wiaPrivateJwk,
      publicJwk: wiaPublicJwk,
      issuer: wiaIssuer,
      audience: tokenEndpoint,
      alg: "ES256",
      ttlHours: 1
    });
    console.log("[codeflow] WIA generated for token request"); try { slog("[codeflow] WIA generated", { hasWIA: !!wiaJwt }); } catch {}
  } catch (wiaError) {
    console.warn("[codeflow] Failed to generate WIA:", wiaError?.message); try { slog("[codeflow] WIA generation failed", { error: wiaError?.message }); } catch {}
  }
  
  // Mirror authorization_details in token request (many issuers expect it)
  const tokenAuthzDetails = [
    {
      type: "openid_credential",
      credential_configuration_id: configurationId,
      ...(issuerMeta?.credential_issuer ? { locations: [issuerMeta.credential_issuer] } : {}),
    },
  ];
  const tokenRes = await httpPostForm(tokenEndpoint, {
    grant_type: "authorization_code",
    code,
    code_verifier: codeVerifier,
    client_id: "wallet-client",
    redirect_uri: redirectUri,
    authorization_details: JSON.stringify(tokenAuthzDetails),
    ...(wiaJwt ? { client_assertion: wiaJwt, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" } : {}),
  }, logSessionId, dpopJwt);
  console.log("[codeflow] tokenRes.status=", tokenRes.status); try { slog("[codeflow] tokenRes.status", { status: tokenRes.status }); } catch {}
  if (!tokenRes.ok) {
    const text = await tokenRes.text().catch(() => "");
    console.error("[codeflow] token error", tokenRes.status, text?.slice(0, 500));
    let err = {};
    try { err = JSON.parse(text); } catch {}
    try { slog("[codeflow] token error", { status: tokenRes.status, err }); } catch {}
    throw new Error(`token_error ${tokenRes.status}: ${JSON.stringify(err)}`);
  }
  const tokenBody = await tokenRes.json();
  const accessToken = tokenBody.access_token;
  let c_nonce = tokenBody.c_nonce;
  let c_nonce_expires_in = tokenBody.c_nonce_expires_in;
  console.log("[codeflow] got access_token=", accessToken ? "yes" : "no", "c_nonce=", c_nonce ? "yes" : "no"); try { slog("[codeflow] token received", { hasAccessToken: !!accessToken, hasCNonce: !!c_nonce }); } catch {}
  if (c_nonce) {
    console.log("[codeflow] using c_nonce from token response"); try { slog("[codeflow] using c_nonce from token"); } catch {}
  } else if (issuerMeta.nonce_endpoint) {
    const nonceEndpoint = issuerMeta.nonce_endpoint;
    console.log("[codeflow] nonceEndpoint=", nonceEndpoint); try { slog("[codeflow] nonceEndpoint", { nonceEndpoint }); } catch {}
    const nonceRes = await httpPostJson(nonceEndpoint, {}, logSessionId); try { slog("[codeflow] nonce request", { endpoint: nonceEndpoint, status: nonceRes.status }); } catch {}
    if (!nonceRes.ok) {
      const text = await nonceRes.text().catch(() => "");
      console.error("[codeflow] nonce error", nonceRes.status, text?.slice(0, 500)); try { slog("[codeflow] nonce error", { status: nonceRes.status, error: text?.slice(0, 200) }); } catch {}
      let err = {};
      try { err = JSON.parse(text); } catch {}
      throw new Error(`nonce_error ${nonceRes.status}: ${JSON.stringify(err)}`);
    }
    const nonceJson = await nonceRes.json();
    c_nonce = nonceJson.c_nonce;
    c_nonce_expires_in = nonceJson.c_nonce_expires_in;
  } else {
    console.log("[codeflow] no c_nonce in token and no nonce_endpoint; proceeding without nonce"); try { slog("[codeflow] no c_nonce available"); } catch {}
  }

  // Algorithm negotiation
  const supportedAlgs2 = issuerMeta?.proof_types_supported?.jwt?.proof_signing_alg_values_supported || issuerMeta?.credential_configurations_supported?.[configurationId]?.proof_types_supported?.jwt?.proof_signing_alg_values_supported || [];
  const preferredOrder2 = ["ES256", "ES384", "ES512", "EdDSA"];
  const selectedAlg2 = (Array.isArray(supportedAlgs2) && supportedAlgs2.length)
    ? (preferredOrder2.find((a) => supportedAlgs2.includes(a)) || supportedAlgs2[0])
    : "ES256";
  console.log("[codeflow] issuer supported proof algs:", supportedAlgs2); try { slog("[codeflow] supported algs", { supportedAlgs: supportedAlgs2 }); } catch {}
  console.log("[codeflow] selected proof alg:", selectedAlg2); try { slog("[codeflow] selected alg", { selectedAlg: selectedAlg2 }); } catch {}

  const aud2 = issuerMeta?.credential_issuer || apiBase;
  console.log("[codeflow] proof audience:", aud2, issuerMeta?.credential_issuer ? "(from issuerMeta.credential_issuer)" : "(fallback apiBase)"); try { slog("[codeflow] proof audience", { aud: aud2 }); } catch {}
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath, selectedAlg2);
  const didJwk = generateDidJwkFromPrivateJwk(publicJwk);

  const credentialEndpoint = issuerMeta.credential_endpoint || `${apiBase}/credential`;
  
  // Generate WUA (Wallet Unit Attestation) for credential request
  let wuaJwt = null;
  try {
    const { privateJwk: wuaPrivateJwk, publicJwk: wuaPublicJwk } = await ensureOrCreateEcKeyPair(keyPath, "ES256");
    const wuaIssuer = generateDidJwkFromPrivateJwk(wuaPublicJwk);
    
    // Create WUA with required claims
    wuaJwt = await createWUA({
      privateJwk: wuaPrivateJwk,
      publicJwk: wuaPublicJwk,
      issuer: wuaIssuer,
      audience: credentialEndpoint,
      attestedKeys: [publicJwk], // Attest the key used for proof
      eudiWalletInfo: {
        general_info: {
          name: "Test Wallet Client",
          version: "1.0.0"
        },
        key_storage_info: {
          storage_type: "software",
          protection_level: "software"
        }
      },
      alg: "ES256",
      ttlHours: 24
    });
    console.log("[codeflow] WUA generated for credential request"); try { slog("[codeflow] WUA generated", { hasWUA: !!wuaJwt }); } catch {}
  } catch (wuaError) {
    console.warn("[codeflow] Failed to generate WUA:", wuaError?.message); try { slog("[codeflow] WUA generation failed", { error: wuaError?.message }); } catch {}
  }
  
  // Include WUA in the proof JWT header as key_attestation (per spec)
  const proofJwt = await createProofJwt({ 
    privateJwk, 
    publicJwk, 
    audience: aud2, 
    nonce: c_nonce, 
    issuer: didJwk, 
    typ: "openid4vci-proof+jwt", 
    alg: selectedAlg2,
    key_attestation: wuaJwt || undefined
  });
  
  console.log("[codeflow] credentialEndpoint=", credentialEndpoint); try { slog("[codeflow] credentialEndpoint", { credentialEndpoint }); } catch {}
  console.log("[codeflow] requesting credential..."); try { slog("[codeflow] requesting credential"); } catch {}
  const credReq = { 
    credential_configuration_id: configurationId, 
    proofs: { 
      jwt: [proofJwt]
    } 
  };
  console.log("[codeflow] credential request:", JSON.stringify({ ...credReq, proofs: { jwt: ["<redacted>"] } }, null, 2)); try { slog("[codeflow] credential request body", { hasBody: true }); } catch {}
  const credRes = await fetch(credentialEndpoint, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
    body: JSON.stringify(credReq),
  });
  console.log("[codeflow] credentialRes.status=", credRes.status); 
  try { slog("[codeflow] credentialRes.status", { status: credRes.status }); } catch {}
  console.log("[codeflow] credentialRes.headers:", Object.fromEntries(credRes.headers.entries())); 
  try { slog("[codeflow] credentialRes.headers", { headers: Object.fromEntries(credRes.headers.entries()) }); } catch {}

  const responseText = await credRes.text().catch(() => "");
  console.log("[codeflow] credentialRes.body length:", responseText.length); 
  try { slog("[codeflow] credentialRes.body", { length: responseText.length }); } catch {}

  if (credRes.status === 202) {
    let credBody;
    try {
      credBody = JSON.parse(responseText);
    } catch (e) {
      console.error("[codeflow] failed to parse deferred response as JSON:", e?.message); 
      try { slog("[codeflow] deferred response parse failed", { error: e?.message, body: responseText?.slice(0, 500) }); } catch {}
      throw new Error(`credential_error ${credRes.status}: invalid JSON response`);
    }
    const { transaction_id } = credBody;
    console.log("[codeflow] deferred issuance, transaction_id:", transaction_id); 
    try { slog("[codeflow] deferred issuance", { transaction_id }); } catch {}
    const start = Date.now();
    const timeout = pollTimeoutMs ?? 30000;
    const interval = pollIntervalMs ?? 2000;
    const deferredEndpoint = issuerMeta.credential_deferred_endpoint || `${apiBase}/credential_deferred`;
    while (Date.now() - start < timeout) {
      await sleep(interval);
      const defRes = await httpPostJson(deferredEndpoint, { transaction_id }, logSessionId); 
      try { slog("[codeflow] deferred poll", { status: defRes.status }); } catch {}
      if (defRes.ok) {
        const defBodyText = await defRes.text().catch(() => "");
        console.log("[codeflow] deferred response body length:", defBodyText.length); 
        try { slog("[codeflow] deferred response", { length: defBodyText.length }); } catch {}
        let defBody;
        try {
          defBody = JSON.parse(defBodyText);
        } catch (e) {
          console.error("[codeflow] failed to parse deferred credential as JSON:", e?.message); 
          try { slog("[codeflow] deferred credential parse failed", { error: e?.message, body: defBodyText?.slice(0, 500) }); } catch {}
          throw new Error(`credential_error: invalid JSON in deferred credential response`);
        }
        try { slog("[codeflow] deferred ready"); } catch {}
        await validateAndStoreCredential({ configurationId, credential: defBody, issuerMeta, apiBase, keyBinding: { privateJwk, publicJwk, didJwk }, metadata: { configurationId, c_nonce, c_nonce_expires_in }, authorizationServerMeta: issuerMeta._authorizationServerMeta }, logSessionId);
        return defBody;
      } else {
        const defErrorText = await defRes.text().catch(() => "");
        console.warn("[codeflow] deferred poll error:", defRes.status, defErrorText?.slice(0, 500)); 
        try { slog("[codeflow] deferred poll error", { status: defRes.status, error: defErrorText?.slice(0, 500) }); } catch {}
      }
    }
    try { slog("[codeflow] deferred timeout"); } catch {}
    throw new Error("timeout: Deferred issuance timed out");
  }

  if (!credRes.ok) {
    let err = {};
    try { 
      err = JSON.parse(responseText); 
    } catch (parseErr) {
      console.error("[codeflow] credential error response is not JSON, raw text:", responseText?.slice(0, 500)); 
      try { slog("[codeflow] credential error not JSON", { text: responseText?.slice(0, 500) }); } catch {}
      err = { error: "invalid_response", error_description: responseText?.slice(0, 500) };
    }
    console.error("[codeflow] credential error parsed:", JSON.stringify(err, null, 2)); 
    try { slog("[codeflow] credential error", { status: credRes.status, err }); } catch {}
    throw new Error(`credential_error ${credRes.status}: ${JSON.stringify(err)}`);
  }
  
  let credBody;
  try {
    credBody = JSON.parse(responseText);
  } catch (e) {
    console.error("[codeflow] failed to parse credential response as JSON:", e?.message); 
    try { slog("[codeflow] credential response parse failed", { error: e?.message, body: responseText?.slice(0, 500) }); } catch {}
    throw new Error(`credential_error: invalid JSON response - ${e?.message}`);
  }
  console.log("[codeflow] credential received, starting validation"); 
  try { slog("[codeflow] credential received", { hasCredential: !!credBody }); } catch {}
  
  try {
    await validateAndStoreCredential({ configurationId, credential: credBody, issuerMeta, apiBase, keyBinding: { privateJwk, publicJwk, didJwk }, metadata: { configurationId, c_nonce, c_nonce_expires_in }, authorizationServerMeta: issuerMeta._authorizationServerMeta }, logSessionId);
  } catch (validationError) {
    console.error("[codeflow] credential validation failed:", validationError?.message || validationError); 
    try { slog("[codeflow] credential validation failed", { error: validationError?.message || String(validationError), stack: validationError?.stack }); } catch {}
    throw validationError;
  }
  return credBody;
}

async function validateAndStoreCredential({ configurationId, credential, issuerMeta, apiBase, keyBinding, metadata, authorizationServerMeta }, logSessionId) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
  
  // Debug: Log credential envelope structure
  console.log("[validate] credential envelope type:", typeof credential, Array.isArray(credential) ? "(array)" : "");
  try { slog("[validate] envelope type", { type: typeof credential, isArray: Array.isArray(credential) }); } catch {}
  if (credential && typeof credential === 'object') {
    console.log("[validate] credential envelope keys:", Object.keys(credential));
    try { slog("[validate] envelope keys", { keys: Object.keys(credential) }); } catch {}
  }
  
  // Extract the token string if envelope is used
  const token = extractCredentialToken(credential);
  console.log("[validate] extracted token type:", typeof token, "length:", typeof token === 'string' ? token.length : 'N/A');
  try { slog("[validate] extracted token", { tokenType: typeof token, length: typeof token === 'string' ? token.length : 'N/A' }); } catch {}
  if (!token) {
    console.error("[validate] could not locate credential token in envelope");
    try { slog("[validate] token extraction failed", { envelopeKeys: credential && typeof credential === 'object' ? Object.keys(credential) : [] }); } catch {}
    throw new Error("credential_format_error: could not locate credential token");
  }

  console.log("[validate] configurationId=", configurationId, "issuer=", issuerMeta?.credential_issuer, "has.c_nonce=", !!metadata?.c_nonce); 
  try { slog("[validate] start", { configurationId, issuer: issuerMeta?.credential_issuer, hasCNonce: !!metadata?.c_nonce }); } catch {}
  console.log("[validate] token preview:", typeof token === 'string' ? token.substring(0, 60) + "..." : typeof token); 
  try { slog("[validate] token preview", { tokenType: typeof token, preview: typeof token === 'string' ? token.substring(0, 100) : typeof token }); } catch {}
  try {
    const dbgFull = process.env.WALLET_DEBUG_CREDENTIAL === 'full';
    const envelopeStr = typeof credential === 'string' ? credential : JSON.stringify(credential);
    const shown = dbgFull ? envelopeStr : envelopeStr.substring(0, 2000);
    console.log("[validate] credential envelope:"+ envelopeStr)
    try { slog("[validate] envelope", { length: envelopeStr.length, mode: dbgFull ? "full" : "truncated" }); } catch {}
  } catch (e) {
    console.warn("[validate] failed to log credential envelope:", e?.message);
    try { slog("[validate] envelope log failed", { error: e?.message }); } catch {}
  }

  // Try SD-JWT first (presence of '~'), else treat as JWT VC; if neither, try mdoc
  try {
    if (typeof token === 'string' && token.includes('~')) {
      console.log("[validate] detected SD-JWT format (contains '~')"); 
      try { slog("[validate] validating SD-JWT"); } catch {}
      await validateSdJwt({ sdJwt: token, issuerMeta, configurationId, expectedCNonce: metadata?.c_nonce, authorizationServerMeta: authorizationServerMeta || issuerMeta._authorizationServerMeta }, logSessionId);
    } else if (typeof token === 'string' && token.split('.').length >= 3) {
      console.log("[validate] detected JWT VC format (3+ parts)"); 
      try { slog("[validate] validating JWT VC"); } catch {}
      await validateJwtVc({ jwtVc: token, issuerMeta, apiBase, configurationId, publicJwk: keyBinding?.publicJwk }, logSessionId);
    } else if (typeof token === 'string') {
      // Potential mdoc base64url
      console.log("[validate] detected potential mdoc format"); 
      try { slog("[validate] validating mdoc"); } catch {}
      const mdocResult = await verifyReceivedMdlToken(token, { validateStructure: true, includeMetadata: false });
      if (!mdocResult.success) {
        console.error("[validate] mdoc validation failed:", mdocResult.error); 
        try { slog("[validate] mdoc validation failed", { error: mdocResult.error }); } catch {}
        throw new Error(`mdoc_validation_failed: ${mdocResult.error}`);
      }
      // Placeholder for cryptographic verification using trust anchors
      if (process.env.WALLET_MDL_STRICT === 'true') {
        try { slog("[validate] mdoc crypto verification not implemented"); } catch {}
        throw new Error("mdoc_crypto_verification_not_implemented: provide trust anchors and crypto verifier");
      }
    } else {
      console.error("[validate] unknown credential format, token type:", typeof token); 
      try { slog("[validate] unknown format", { tokenType: typeof token }); } catch {}
      throw new Error(`credential_format_error: unknown credential format, token type: ${typeof token}`);
    }
  } catch (validationError) {
    console.error("[validate] credential validation error:", validationError?.message || validationError); 
    console.error("[validate] validation error stack:", validationError?.stack); 
    try { slog("[validate] validation error", { error: validationError?.message || String(validationError), stack: validationError?.stack }); } catch {}
    throw validationError;
  }

  // If validation passed, store
  console.log("[validate] credential validation passed, storing"); 
  try { slog("[store] credential", { configurationId }); } catch {}
  await storeWalletCredentialByType(configurationId, { credential, keyBinding, metadata });
}

function extractCredentialToken(credentialEnvelope) {
  if (!credentialEnvelope) return null;
  if (typeof credentialEnvelope === "string") return credentialEnvelope;

  const seen = new Set();
  const candidates = [];
  let fallback = null;

  function isLikelyCredentialString(str) {
    if (typeof str !== "string") return false;
    if (str.includes("~")) return true; // SD-JWT
    if (str.split(".").length >= 3) return true; // JWS-style token
    if (str.length > 80 && /^[A-Za-z0-9._~-]+$/.test(str)) return true; // base64ish (mdoc, etc.)
    return false;
  }

  function visit(value) {
    if (value === null || typeof value === "undefined") return;
    if (typeof value === "string") {
      if (isLikelyCredentialString(value)) {
        candidates.push(value);
      } else if (!fallback) {
        fallback = value;
      }
      return;
    }

    if (typeof value !== "object") return;
    if (seen.has(value)) return;
    seen.add(value);

    if (Array.isArray(value)) {
      for (const entry of value) visit(entry);
      return;
    }

    if (Object.prototype.hasOwnProperty.call(value, "credential")) {
      visit(value.credential);
    }
    if (Object.prototype.hasOwnProperty.call(value, "credentials")) {
      visit(value.credentials);
    }

    for (const key of Object.keys(value)) {
      if (key === "credential" || key === "credentials") continue;
      visit(value[key]);
    }
  }

  visit(credentialEnvelope);
  return candidates[0] || fallback;
}

async function validateSdJwt({ sdJwt, issuerMeta, configurationId, expectedCNonce, authorizationServerMeta }, logSessionId) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
  console.log("[sd-jwt] start validation; configurationId=", configurationId); try { slog("[sd-jwt] start validation", { configurationId }); } catch {}
  // Decode and reconstruct claims (verifies disclosures/digests)
  const decoded = await decodeSdJwt(sdJwt, digest);
  console.log("[sd-jwt] decoded header.alg=", decoded.jwt.header?.alg, "kid=", decoded.jwt.header?.kid); try { slog("[sd-jwt] decoded header", { alg: decoded.jwt.header?.alg, kid: decoded.jwt.header?.kid }); } catch {}
  // Throws if disclosures invalid
  await getClaims(decoded.jwt.payload, decoded.disclosures, digest);
  console.log("[sd-jwt] disclosures/digests verified; vct=", decoded.jwt.payload?.vct); try { slog("[sd-jwt] disclosures verified", { vct: decoded.jwt.payload?.vct }); } catch {}

  // Extract JWS and header once
  const jws = sdJwt.split('~')[0];
  let hdr = {};
  try { hdr = decodeProtectedHeader(jws); } catch {}
  let signatureVerified = false;
  // DID-based signature verification (did:web, did:jwk)
  if ((hdr.kid && hdr.kid.startsWith('did:')) || (decoded.jwt.payload?.iss && String(decoded.jwt.payload.iss).startsWith('did:'))) {
    try {
      const didIssuer = (hdr.kid && hdr.kid.split('#')[0]) || String(decoded.jwt.payload.iss);
      console.log("[sd-jwt] attempting DID-based verification using", didIssuer); try { slog("[sd-jwt] attempting DID verification", { didIssuer }); } catch {}
      await verifyJwsWithDid(jws, hdr, decoded.jwt.payload?.iss);
      console.log("[sd-jwt] DID-based JWS signature verified"); try { slog("[sd-jwt] DID signature verified"); } catch {}
      signatureVerified = true;
    } catch (e) {
      console.warn("[sd-jwt] DID-based verification failed:", e?.message || e); try { slog("[sd-jwt] DID verification failed", { error: e?.message || String(e) }); } catch {}
    }
  }
  // If x5c present, try x509 cert verification (only if not already verified)
  if (!signatureVerified && Array.isArray(hdr.x5c) && hdr.x5c.length > 0) {
    const pem = base64DerToPem(hdr.x5c[0]);
    try {
      const certKey = await importX509(pem, hdr.alg || 'ES256');
      await jwtVerify(jws, certKey, { clockTolerance: 300 });
      console.log("[sd-jwt] JWS signature verified via x5c certificate"); try { slog("[sd-jwt] x5c signature verified"); } catch {}
      signatureVerified = true;
    } catch (e) {
      console.warn("[sd-jwt] x5c certificate verification failed:", e?.message || e); try { slog("[sd-jwt] x5c verification failed", { error: e?.message || String(e) }); } catch {}
    }
  }

  // Verify issuer signature of SD-JWT JWS
  // Per OIDC4VCI v1.0: Use jwks_uri from credential issuer metadata, or from authorization server metadata,
  // or fall back to /.well-known/jwt-vc-issuer endpoint (which may contain jwks_uri or jwks)
  let jwksUrl = issuerMeta?.jwks_uri || null;
  if (!jwksUrl && authorizationServerMeta?.jwks_uri) {
    jwksUrl = authorizationServerMeta.jwks_uri;
    console.log("[sd-jwt] using jwks_uri from authorization server metadata:", jwksUrl);
    try { slog("[sd-jwt] using AS jwks_uri", { jwksUrl }); } catch {}
  }
  let jwtVcIssuerMeta = null;
  if (!jwksUrl && issuerMeta?.credential_issuer) {
    // Fallback to JWT VC Issuer metadata endpoint (from JWT VC Issuer metadata spec)
    const jwtVcIssuerUrl = `${issuerMeta.credential_issuer.replace(/\/$/, '')}/.well-known/jwt-vc-issuer`;
    console.log("[sd-jwt] fetching JWT VC Issuer metadata from:", jwtVcIssuerUrl);
    try { slog("[sd-jwt] fetching jwt-vc-issuer metadata", { url: jwtVcIssuerUrl }); } catch {}
    try {
      const jwtVcRes = await fetch(jwtVcIssuerUrl);
      if (jwtVcRes.ok) {
        jwtVcIssuerMeta = await jwtVcRes.json();
        jwksUrl = jwtVcIssuerMeta?.jwks_uri || null;
        if (jwksUrl) {
          console.log("[sd-jwt] found jwks_uri in JWT VC Issuer metadata:", jwksUrl);
          try { slog("[sd-jwt] jwt-vc-issuer jwks_uri", { jwksUrl }); } catch {}
        } else if (jwtVcIssuerMeta?.jwks) {
          // JWT VC Issuer metadata may contain jwks directly
          console.log("[sd-jwt] JWT VC Issuer metadata contains jwks directly");
          try { slog("[sd-jwt] jwt-vc-issuer has jwks", { hasJwks: !!jwtVcIssuerMeta.jwks }); } catch {}
        }
      } else {
        console.warn("[sd-jwt] JWT VC Issuer metadata fetch failed:", jwtVcRes.status);
        try { slog("[sd-jwt] jwt-vc-issuer fetch failed", { status: jwtVcRes.status }); } catch {}
      }
    } catch (e) {
      console.warn("[sd-jwt] JWT VC Issuer metadata fetch error:", e?.message || e);
      try { slog("[sd-jwt] jwt-vc-issuer fetch error", { error: e?.message || String(e) }); } catch {}
    }
  }
  let jwksFetchStatus = null;
  let jwksKeysCount = 0;
  let jwksVerificationError = null;
  
  if (!signatureVerified && jwksUrl) {
    console.log("[sd-jwt] fetching JWKS from:", jwksUrl); try { slog("[sd-jwt] fetching JWKS", { jwksUrl }); } catch {}
    const res = await fetch(jwksUrl);
    jwksFetchStatus = res.status;
    console.log("[sd-jwt] JWKS fetch status:", res.status); try { slog("[sd-jwt] JWKS fetch status", { status: res.status }); } catch {}
    if (res.ok) {
      const body = await res.json();
      const jwks = body.keys ? body : body.jwks ? body.jwks : null;
      jwksKeysCount = jwks?.keys?.length || (Array.isArray(jwks) ? jwks.length : 0);
      console.log("[sd-jwt] JWKS keys count:", jwksKeysCount); 
      try { slog("[sd-jwt] JWKS keys count", { count: jwksKeysCount }); } catch {}
      if (jwks) {
        // hdr and jws are already computed above
        console.log("[sd-jwt] JWS header.alg=", hdr.alg, "kid=", hdr.kid); 
        try { slog("[sd-jwt] JWS header", { alg: hdr.alg, kid: hdr.kid }); } catch {}
        const JWKS = createLocalJWKSet(jwks);
        try {
          await jwtVerify(jws, JWKS, { clockTolerance: 300 });
          console.log("[sd-jwt] JWS signature verified"); try { slog("[sd-jwt] JWS signature verified"); } catch {}
          signatureVerified = true;
        } catch (e) {
          jwksVerificationError = e?.message || String(e);
          console.error("[sd-jwt] JWS signature verification failed with JWKS resolver:", e?.message || e);
          console.error("[sd-jwt] verification error details:", e);
          try { slog("[sd-jwt] JWKS resolver failed", { error: e?.message || String(e), errorName: e?.name, errorCode: e?.code }); } catch {}
          // Fallback: iterate keys if no kid or resolver failed
          const keysArr = Array.isArray(jwks.keys) ? jwks.keys : jwks.keys ? jwks.keys : jwks;
          if (Array.isArray(keysArr) && keysArr.length > 0) {
            let verified = false;
            const keyErrors = [];
            for (const [idx, jwk] of keysArr.entries()) {
              if (jwk.use && jwk.use !== 'sig') {
                console.log(`[sd-jwt] Skipping key[${idx}] - use=${jwk.use} (not 'sig')`); 
                continue;
              }
              if (jwk.kty && jwk.kty !== 'EC') {
                console.log(`[sd-jwt] Skipping key[${idx}] - kty=${jwk.kty} (not 'EC')`); 
                continue;
              }
              try {
                console.log(`[sd-jwt] Trying key[${idx}] kid=${jwk.kid || 'none'} crv=${jwk.crv} kty=${jwk.kty}`); 
                try { slog(`[sd-jwt] trying key ${idx}`, { kid: jwk.kid, crv: jwk.crv, kty: jwk.kty }); } catch {}
                const key = await importJWK(jwk, hdr.alg || 'ES256');
                await jwtVerify(jws, key, { clockTolerance: 300 });
                console.log(`[sd-jwt] Verified with key[${idx}]`); try { slog(`[sd-jwt] verified with key ${idx}`); } catch {}
                verified = true;
                break;
              } catch (err) {
                const errMsg = err?.message || String(err);
                keyErrors.push(`key[${idx}](${jwk.kid || 'no-kid'}): ${errMsg}`);
                console.warn(`[sd-jwt] key[${idx}] failed:`, errMsg); 
                try { slog(`[sd-jwt] key ${idx} failed`, { error: errMsg, kid: jwk.kid }); } catch {}
              }
            }
            if (!verified) {
              console.error("[sd-jwt] all JWKS keys failed verification");
              console.error("[sd-jwt] tried", keysArr.length, "keys");
              console.error("[sd-jwt] key errors:", keyErrors.join('; '));
              try { slog("[sd-jwt] all keys failed", { keyCount: keysArr.length, keyErrors }); } catch {}
              jwksVerificationError = `all ${keysArr.length} JWKS keys failed verification: ${keyErrors.join('; ')}`;
              throw new Error(`signature verification failed: all JWKS keys failed verification`);
            }
            signatureVerified = true;
          } else {
            console.error("[sd-jwt] no valid keys found in JWKS");
            try { slog("[sd-jwt] no valid keys", { jwksStructure: typeof jwks }); } catch {}
            jwksVerificationError = 'no valid keys found in JWKS';
            throw new Error('signature verification failed: no valid keys found in JWKS');
          }
        }
      } else {
        jwksVerificationError = 'JWKS response does not contain keys';
        console.error("[sd-jwt] JWKS response does not contain keys");
        try { slog("[sd-jwt] JWKS no keys", { bodyKeys: Object.keys(body) }); } catch {}
      }
    } else {
      const errorText = await res.text().catch(() => "");
      jwksVerificationError = `JWKS fetch failed with status ${res.status}${errorText ? `: ${errorText.slice(0, 200)}` : ''}`;
      console.warn("[sd-jwt] JWKS fetch failed; status:", res.status, "body:", errorText?.slice(0, 200)); 
      try { slog("[sd-jwt] JWKS fetch failed", { status: res.status, error: errorText?.slice(0, 200) }); } catch {}
    }
  }

  if (!signatureVerified) {
    const reasons = [];
    if (!hdr.kid && !decoded.jwt.payload?.iss?.startsWith('did:')) reasons.push('no DID identifier found');
    if (!Array.isArray(hdr.x5c) || hdr.x5c.length === 0) reasons.push('no x5c certificate found');
    if (!jwksUrl) {
      reasons.push('no JWKS URI available');
    } else if (jwksFetchStatus !== null) {
      if (jwksFetchStatus !== 200) {
        reasons.push(`JWKS fetch failed (HTTP ${jwksFetchStatus})`);
      } else if (jwksVerificationError) {
        reasons.push(`JWKS verification failed: ${jwksVerificationError}`);
      } else if (jwksKeysCount === 0) {
        reasons.push('JWKS contains no keys');
      } else {
        reasons.push(`JWKS verification failed (${jwksKeysCount} keys available)`);
      }
    }
    const reasonStr = reasons.length > 0 ? ` - reasons: ${reasons.join(', ')}` : '';
    console.error("[sd-jwt] signature verification failed", reasonStr);
    console.error("[sd-jwt] header:", JSON.stringify(hdr, null, 2));
    console.error("[sd-jwt] issuer from payload:", decoded.jwt.payload?.iss);
    console.error("[sd-jwt] JWKS URL attempted:", jwksUrl || 'none');
    console.error("[sd-jwt] JWKS fetch status:", jwksFetchStatus || 'not attempted');
    console.error("[sd-jwt] JWKS keys count:", jwksKeysCount || 'unknown');
    console.error("[sd-jwt] signature verification methods attempted: DID=", (hdr.kid && hdr.kid.startsWith('did:')) || (decoded.jwt.payload?.iss && String(decoded.jwt.payload.iss).startsWith('did:')), "x5c=", Array.isArray(hdr.x5c) && hdr.x5c.length > 0, "JWKS=", !!jwksUrl);
    try { slog("[sd-jwt] signature verification failed", { reasons, header: hdr, issuer: decoded.jwt.payload?.iss, jwksUrl, jwksFetchStatus, jwksKeysCount, jwksVerificationError, triedDid: (hdr.kid && hdr.kid.startsWith('did:')) || (decoded.jwt.payload?.iss && String(decoded.jwt.payload.iss).startsWith('did:')), triedX5c: Array.isArray(hdr.x5c) && hdr.x5c.length > 0, triedJwks: !!jwksUrl }); } catch {}
    throw new Error(`signature verification failed${reasonStr}`);
  }

  // Validate kb-jwt binding and c_nonce
  if (decoded.kbJwt && expectedCNonce) {
    try {
      const kbDecoded = decodeJwt(decoded.kbJwt);
      console.log("[sd-jwt] kb-jwt nonce=", kbDecoded?.nonce, "expected=", expectedCNonce); try { slog("[sd-jwt] kb-jwt nonce check", { hasNonce: !!kbDecoded?.nonce, nonceMatches: kbDecoded?.nonce === expectedCNonce }); } catch {}
      if (kbDecoded?.nonce && kbDecoded.nonce !== expectedCNonce) {
        throw new Error("kb_jwt_nonce_mismatch");
      }
    } catch (e) {
      // If decode fails, do a soft fail
      console.error("[sd-jwt] kb-jwt decode failed:", e?.message || e); try { slog("[sd-jwt] kb-jwt decode failed", { error: e?.message || String(e) }); } catch {}
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

async function validateJwtVc({ jwtVc, issuerMeta, apiBase, configurationId, publicJwk }, logSessionId) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
  console.log("[jwt-vc] start validation; configurationId=", configurationId);
  try { slog("[jwt-vc] start validation", { configurationId }); } catch {}
  let hdr = {};
  let payloadFromDid, payloadFromX5c;
  try {
    hdr = decodeProtectedHeader(jwtVc);
    console.log("[jwt-vc] header.alg=", hdr.alg, "kid=", hdr.kid);
    try { slog("[jwt-vc] header", { alg: hdr.alg, kid: hdr.kid }); } catch {}
    // DID-based verification first if kid/iss is DID
    if ((hdr.kid && hdr.kid.startsWith('did:')) || (issuerMeta?.credential_issuer?.startsWith('did:') || false)) {
      try {
        const didIssuer = (hdr.kid && hdr.kid.split('#')[0]) || issuerMeta?.credential_issuer;
        console.log("[jwt-vc] attempting DID-based verification using", didIssuer);
        try { slog("[jwt-vc] attempting DID verification", { didIssuer }); } catch {}
        const verified = await verifyJwsWithDid(jwtVc, hdr, didIssuer);
        payloadFromDid = verified?.payload;
        if (payloadFromDid) {
          console.log("[jwt-vc] signature verified via DID");
          try { slog("[jwt-vc] DID signature verified"); } catch {}
        }
      } catch (e) {
        console.warn("[jwt-vc] DID-based verification failed:", e?.message || e);
        try { slog("[jwt-vc] DID verification failed", { error: e?.message || String(e) }); } catch {}
      }
    }
    if (Array.isArray(hdr.x5c) && hdr.x5c.length > 0) {
      const pem = base64DerToPem(hdr.x5c[0]);
      try {
        const certKey = await importX509(pem, hdr.alg || 'ES256');
        const verified = await jwtVerify(jwtVc, certKey, { clockTolerance: 300 });
        console.log("[jwt-vc] signature verified via x5c certificate");
        try { slog("[jwt-vc] x5c signature verified"); } catch {}
        // Use payload from verified path
        payloadFromX5c = verified.payload;
      } catch (e) {
        console.warn("[jwt-vc] x5c certificate verification failed:", e?.message || e);
        try { slog("[jwt-vc] x5c verification failed", { error: e?.message || String(e) }); } catch {}
      }
    }
  } catch (e) {
    console.error("[jwt-vc] failed to decode header:", e?.message || e);
    try { slog("[jwt-vc] header decode failed", { error: e?.message || String(e) }); } catch {}
  }
  // Validate JWT VC signature using issuer JWKS
  const jwksUrl = issuerMeta?.jwks_uri || `${apiBase}/jwks`;
  let payload = typeof payloadFromDid !== 'undefined' ? payloadFromDid : (typeof payloadFromX5c !== 'undefined' ? payloadFromX5c : undefined);
  if (jwksUrl) {
    console.log("[jwt-vc] fetching JWKS from:", jwksUrl);
    try { slog("[jwt-vc] fetching JWKS", { jwksUrl }); } catch {}
    const res = await fetch(jwksUrl);
    console.log("[jwt-vc] JWKS fetch status:", res.status);
    try { slog("[jwt-vc] JWKS fetch status", { status: res.status }); } catch {}
    if (res.ok) {
      const jwks = await res.json();
      const keysCount = jwks?.keys?.length || 0;
      console.log("[jwt-vc] JWKS keys count:", keysCount);
      try { slog("[jwt-vc] JWKS keys count", { count: keysCount }); } catch {}
      if (!payload) {
        const JWKS = createLocalJWKSet(jwks.keys ? jwks : { keys: jwks.keys || [] });
        try {
          const verified = await jwtVerify(jwtVc, JWKS, { clockTolerance: 300 });
          payload = verified.payload;
          console.log("[jwt-vc] signature verified");
          try { slog("[jwt-vc] JWS signature verified"); } catch {}
        } catch (e) {
          console.error("[jwt-vc] signature verification failed with JWKS resolver:", e?.message || e);
          console.error("[jwt-vc] verification error details:", e);
          try { slog("[jwt-vc] JWKS resolver failed", { error: e?.message || String(e), errorName: e?.name, errorCode: e?.code }); } catch {}
          // Fallback: iterate keys
          const hdr2 = hdr || (()=>{ try { return decodeProtectedHeader(jwtVc); } catch { return {}; } })();
          const keysArr = Array.isArray(jwks.keys) ? jwks.keys : jwks.keys ? jwks.keys : jwks;
          if (Array.isArray(keysArr) && keysArr.length > 0) {
            for (const [idx, jwk] of keysArr.entries()) {
              if (jwk.use && jwk.use !== 'sig') continue;
              try {
                console.log(`[jwt-vc] Trying key[${idx}] kid=${jwk.kid || 'none'} alg=${hdr2.alg}`);
                try { slog(`[jwt-vc] trying key ${idx}`, { kid: jwk.kid, alg: hdr2.alg }); } catch {}
                const key = await importJWK(jwk, hdr2.alg || 'ES256');
                const verified = await jwtVerify(jwtVc, key, { clockTolerance: 300 });
                payload = verified.payload;
                console.log(`[jwt-vc] Verified with key[${idx}]`);
                try { slog(`[jwt-vc] verified with key ${idx}`); } catch {}
                break;
              } catch (err) {
                console.warn(`[jwt-vc] key[${idx}] failed:`, err?.message || err);
                try { slog(`[jwt-vc] key ${idx} failed`, { error: err?.message || String(err) }); } catch {}
              }
            }
            if (!payload) {
              console.error("[jwt-vc] all JWKS keys failed verification");
              console.error("[jwt-vc] tried", keysArr.length, "keys");
              try { slog("[jwt-vc] all keys failed", { keyCount: keysArr.length }); } catch {}
              throw new Error('signature verification failed: all JWKS keys failed verification');
            }
          } else {
            console.error("[jwt-vc] no valid keys found in JWKS");
            try { slog("[jwt-vc] no valid keys", { jwksStructure: typeof jwks }); } catch {}
            throw new Error('signature verification failed: no valid keys found in JWKS');
          }
        }
      }
    } else {
      console.warn("[jwt-vc] JWKS fetch failed; will decode without verify");
      try { slog("[jwt-vc] JWKS fetch failed", { status: res.status }); } catch {}
    }
  }
  if (!payload) {
    console.warn("[jwt-vc] no verified payload, decoding without verification");
    try { slog("[jwt-vc] decoding without verification"); } catch {}
    payload = decodeJwt(jwtVc);
  }

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
  if (did.startsWith('did:key:')) {
    // Use shared crypto utility to resolve did:key to JWKS
    try {
      const jwks = await didKeyToJwks(did);
      const first = Array.isArray(jwks?.keys) && jwks.keys.length ? jwks.keys[0] : null;
      if (first) {
        return { verificationMethod: [{ id: did + '#0', type: 'JsonWebKey2020', publicKeyJwk: first }] };
      }
      throw new Error('did:key resolution returned no keys');
    } catch (e) {
      throw new Error('did:key resolution failed');
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
      const verified = await jwtVerify(jws, key, { clockTolerance: 300 });
      return verified;
    } catch (e) {
      lastErr = e;
      // continue
    }
  }
  throw lastErr || new Error('DID verification failed');
}







