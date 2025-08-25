import express from "express";
import fetch from "node-fetch";
import { createProofJwt, generateDidJwkFromPrivateJwk, ensureOrCreateEcKeyPair, createPkcePair } from "./lib/crypto.js";
import { performPresentation, resolveDeepLinkFromEndpoint } from "./lib/presentation.js";
import { storeWalletCredentialByType } from "./lib/cache.js";

const app = express();
app.use(express.json({ limit: "2mb" }));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// POST /issue
// body: { issuer: string (default http://localhost:3000), offer?: string, fetchOfferPath?: string, credential?: string }
app.post("/issue", async (req, res) => {
  try {
    const issuerBase = (req.body.issuer || "http://localhost:3000").replace(/\/$/, "");
    const deepLink = req.body.offer || (await getOfferDeepLink(issuerBase, req.body.fetchOfferPath, req.body.credential));
    if (!deepLink) {
      return res.status(400).json({ error: "invalid_request", error_description: "Missing offer or fetchOfferPath" });
    }

    const offerConfig = await resolveOfferConfig(deepLink);
    const { credential_configuration_ids, grants } = offerConfig;
    const apiBase = (offerConfig.credential_issuer || issuerBase).replace(/\/$/, "");
    const configurationId = req.body.credential || credential_configuration_ids?.[0];
    if (!configurationId) {
      return res.status(400).json({ error: "invalid_request", error_description: "No credential_configuration_id available" });
    }

    const preAuthGrant = grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
    if (!preAuthGrant) {
      return res.status(400).json({ error: "unsupported_grant_type", error_description: "Only pre-authorized_code supported" });
    }

    const preAuthorizedCode = preAuthGrant["pre-authorized_code"]; // sessionId
    const txCode = preAuthGrant?.tx_code ? makeTxCode(preAuthGrant.tx_code) : undefined;

    const tokenEndpoint = `${apiBase}/token_endpoint`;
    const tokenRes = await httpPostJson(tokenEndpoint, {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": preAuthorizedCode,
      ...(txCode ? { tx_code: txCode } : {}),
    });
    if (!tokenRes.ok) return forwardError(res, tokenRes, "token_error");
    const tokenBody = await tokenRes.json();
    const accessToken = tokenBody.access_token;

    const nonceEndpoint = `${apiBase}/nonce`;
    const nonceRes = await httpPostJson(nonceEndpoint, {});
    if (!nonceRes.ok) return forwardError(res, nonceRes, "nonce_error");
    const { c_nonce } = await nonceRes.json();

    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(req.body.keyPath);
    const didJwk = generateDidJwkFromPrivateJwk(publicJwk);
    const proofJwt = await createProofJwt({ privateJwk, publicJwk, audience: apiBase, nonce: c_nonce, issuer: didJwk });

    const credentialEndpoint = `${apiBase}/credential`;
    const credReq = { credential_configuration_id: configurationId, proof: { proof_type: "jwt", jwt: proofJwt } };
    const credRes = await fetch(credentialEndpoint, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(credReq),
    });

    if (credRes.status === 202) {
      const { transaction_id } = await credRes.json();
      const start = Date.now();
      const timeout = req.body.pollTimeoutMs ?? 30000;
      const interval = req.body.pollIntervalMs ?? 2000;
      while (Date.now() - start < timeout) {
        await sleep(interval);
        const defRes = await httpPostJson(`${apiBase}/credential_deferred`, { transaction_id });
        if (defRes.ok) {
          const body = await defRes.json();
          await storeWalletCredentialByType(configurationId, {
            credential: body,
            keyBinding: { privateJwk, publicJwk, didJwk },
            metadata: { configurationId, c_nonce },
          });
          return res.json(body);
        }
      }
      return res.status(504).json({ error: "timeout", error_description: "Deferred issuance timed out" });
    }

    if (!credRes.ok) return forwardError(res, credRes, "credential_error");
    const credBody = await credRes.json();
    await storeWalletCredentialByType(configurationId, {
      credential: credBody,
      keyBinding: { privateJwk, publicJwk, didJwk },
      metadata: { configurationId, c_nonce },
    });
    return res.json(credBody);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error", error_description: e.message || String(e) });
  }
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

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
    if (!deepLink) return res.status(400).json({ error: "invalid_request", error_description: "Missing offer or fetchOfferPath" });

    const offerCfg = await resolveOfferConfig(deepLink);
    const { credential_configuration_ids, grants } = offerCfg;
    const apiBase = (offerCfg.credential_issuer || issuerBaseInput).replace(/\/$/, "");

    // Expect authorization_code grant
    const authGrant = grants?.authorization_code;
    if (!authGrant?.issuer_state) return res.status(400).json({ error: "unsupported_grant_type", error_description: "authorization_code grant with issuer_state required" });

    const configurationId = req.body.credential || credential_configuration_ids?.[0];
    if (!configurationId) return res.status(400).json({ error: "invalid_request", error_description: "No credential_configuration_id available" });

    // Build authorize URL per codeFlowSdJwtRoutes expectations
    const { codeVerifier, codeChallenge, codeChallengeMethod } = createPkcePair();
    const state = randomState();
    const clientIdScheme = req.body.clientIdScheme || "redirect_uri";
    const redirectUri = "openid4vp://";
    const issuerState = authGrant.issuer_state;

    // The authorize endpoint lives at apiBase/authorize
    const authorize = new URL(apiBase + "/authorize");
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("issuer_state", issuerState);
    authorize.searchParams.set("state", state);
    authorize.searchParams.set("client_id", "wallet-client");
    authorize.searchParams.set("redirect_uri", redirectUri);
    authorize.searchParams.set("code_challenge", codeChallenge);
    authorize.searchParams.set("code_challenge_method", codeChallengeMethod);
    authorize.searchParams.set("scope", configurationId);

    // Kick off authorization - server responds with redirect_uri that contains ?code=...&state=...
    const authRes = await fetch(authorize.toString(), { redirect: "manual" });
    let redirectUrl = authRes.headers.get("location");
    if (!redirectUrl) {
      const bodyText = await authRes.text().catch(() => "");
      const redirectPayload = safeParseJson(bodyText);
      if (redirectPayload?.redirect_uri) redirectUrl = redirectPayload.redirect_uri;
      else if (/^openid4vp:\/\//.test(bodyText)) redirectUrl = bodyText;
    }
    if (!redirectUrl) return forwardError(res, authRes, "authorize_error");
    const redirect = new URL(redirectUrl);
    const code = redirect.searchParams.get("code");
    const returnedState = redirect.searchParams.get("state");
    if (!code) return res.status(400).json({ error: "invalid_response", error_description: "Authorization code missing" });

    // Exchange code for token
    const tokenEndpoint = `${apiBase}/token_endpoint`;
    const tokenRes = await httpPostJson(tokenEndpoint, {
      grant_type: "authorization_code",
      code,
      code_verifier: codeVerifier,
    });
    if (!tokenRes.ok) return forwardError(res, tokenRes, "token_error");
    const tokenBody = await tokenRes.json();
    const accessToken = tokenBody.access_token;

    // Obtain c_nonce
    const nonceEndpoint = `${apiBase}/nonce`;
    const nonceRes = await httpPostJson(nonceEndpoint, {});
    if (!nonceRes.ok) return forwardError(res, nonceRes, "nonce_error");
    const { c_nonce } = await nonceRes.json();

    // Build proof and request credential
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(req.body.keyPath);
    const didJwk = generateDidJwkFromPrivateJwk(publicJwk);
    const proofJwt = await createProofJwt({ privateJwk, publicJwk, audience: apiBase, nonce: c_nonce, issuer: didJwk });

    const credentialEndpoint = `${apiBase}/credential`;
    const credReq = { credential_configuration_id: configurationId, proof: { proof_type: "jwt", jwt: proofJwt } };
    const credRes = await fetch(credentialEndpoint, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(credReq),
    });

    if (credRes.status === 202) {
      const { transaction_id } = await credRes.json();
      const start = Date.now();
      const timeout = req.body.pollTimeoutMs ?? 30000;
      const interval = req.body.pollIntervalMs ?? 2000;
      while (Date.now() - start < timeout) {
        await sleep(interval);
        const defRes = await httpPostJson(`${apiBase}/credential_deferred`, { transaction_id });
        if (defRes.ok) {
          const body = await defRes.json();
          await storeWalletCredentialByType(configurationId, {
            credential: body,
            keyBinding: { privateJwk, publicJwk, didJwk },
            metadata: { configurationId, c_nonce },
          });
          return res.json(body);
        }
      }
      return res.status(504).json({ error: "timeout", error_description: "Deferred issuance timed out" });
    }

    if (!credRes.ok) return forwardError(res, credRes, "credential_error");
    const credBody2 = await credRes.json();
    await storeWalletCredentialByType(configurationId, {
      credential: credBody2,
      keyBinding: { privateJwk, publicJwk, didJwk },
      metadata: { configurationId, c_nonce },
    });
    return res.json(credBody2);
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
  const res = await fetch(url.toString());
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
  const res = await fetch(offerUri);
  if (!res.ok) throw new Error(`Offer-config error ${res.status}`);
  return res.json();
}

function makeTxCode(cfg) {
  if (cfg?.input_mode === "numeric" && typeof cfg?.length === "number") {
    return "".padStart(cfg.length, "1");
  }
  return undefined;
}

async function httpPostJson(url, body) {
  return fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) });
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


