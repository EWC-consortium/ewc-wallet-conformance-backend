import fetch from "node-fetch";
import { createProofJwt, generateDidJwkFromPrivateJwk, ensureOrCreateEcKeyPair } from "./crypto.js";
import { getWalletCredentialByType, listWalletCredentialTypes, appendWalletLog } from "./cache.js";

function makeSessionLogger(sessionId) {
  return function sessionLog(...args) {
    try { console.log(...args); } catch {}
    if (!sessionId) return;
    try {
      const message = args.map((a) => {
        if (typeof a === 'string') return a;
        try { return JSON.stringify(a); } catch { return String(a); }
      }).join(' ');
      appendWalletLog(sessionId, { level: 'info', message }).catch(() => {});
    } catch {}
  };
}

function parseOpenId4VpDeepLink(deepLink) {
  console.log("[present] Parsing deep link:", deepLink);
  const url = new URL(deepLink);
  if (url.protocol !== "openid4vp:") throw new Error("Unsupported request scheme");
  const requestUri = url.searchParams.get("request_uri");
  const clientId = url.searchParams.get("client_id");
  const method = url.searchParams.get("request_uri_method") || "get";
  console.log("[present] Parsed deep link →", { requestUri, clientId, method });
  return { requestUri, clientId, method };
}

async function fetchAuthorizationRequestJwt(requestUri, method) {
  if (!requestUri) throw new Error("Missing request_uri in deep link");
  if (method && method.toLowerCase() === "post") {
    const form = new URLSearchParams();
    // Optionally include wallet hints; server tolerates empty payload
    console.log("[present] Fetching request JWT via POST:", requestUri);
    const res = await fetch(requestUri, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    const text = await res.text().catch(() => "");
    console.log("[present] POST request_uri status:", res.status, "body.len=", text?.length);
    if (!res.ok) throw new Error(`Auth request POST error ${res.status}${text ? ": " + text.slice(0, 300) : ""}`);
    return text;
  }
  console.log("[present] Fetching request JWT via GET:", requestUri);
  const res = await fetch(requestUri);
  const text = await res.text().catch(() => "");
  console.log("[present] GET request_uri status:", res.status, "body.len=", text?.length);
  if (!res.ok) throw new Error(`Auth request GET error ${res.status}`);
  return text;
}

function decodeJwt(token) {
  const parts = token.split(".");
  if (parts.length < 2) throw new Error("Invalid JWT");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  console.log("[present] Decoded request JWT header.alg=", header.alg, "payload.keys=", Object.keys(payload));
  return { header, payload };
}

function buildPresentationSubmission(presentationDefinition) {
  if (!presentationDefinition) return undefined;
  console.log("[present] Building presentation_submission from definition:", presentationDefinition.id);
  console.log("[present] Input descriptors:", presentationDefinition.input_descriptors?.length || 0);

  const inputDescriptors = presentationDefinition.input_descriptors || [];
  const descriptorMap = inputDescriptors.map((d) => ({ id: d.id, format: inferRootFormat(presentationDefinition), path: "$.vp_token" }));

  console.log("[present] Descriptor map:", JSON.stringify(descriptorMap, null, 2));

  // The verifier expects JSON string in some handlers; keep as string to be safe
  const submission = { definition_id: presentationDefinition.id || "pd", descriptor_map: descriptorMap };
  console.log("[present] Built presentation_submission:", JSON.stringify(submission, null, 2));
  return JSON.stringify(submission);
}

function inferRootFormat(presentationDefinition) {
  // Prefer dc+sd-jwt or vc+sd-jwt if available
  const fmt = presentationDefinition.format || {};
  if (fmt["dc+sd-jwt"]) return "dc+sd-jwt";
  if (fmt["vc+sd-jwt"]) return "vc+sd-jwt";
  if (fmt["jwt_vc_json"]) return "jwt_vc_json";
  return "dc+sd-jwt";
}

function attachKbJwtToSdJwt(sdJwt, kbJwt) {
  if (!sdJwt || typeof sdJwt !== "string") throw new Error("Invalid sd-jwt to present");
  // Trim any trailing '~' to avoid creating empty disclosure segments
  let token = sdJwt;
  while (token.endsWith("~")) token = token.slice(0, -1);
  const parts = token.split("~");
  // kb-jwt is a JWT (has dots) and is appended as the last segment.
  const hasKbJwt = parts.slice(1).some((p) => p.includes("."));
  if (hasKbJwt) return token; // already present
  return `${token}~${kbJwt}`;
}

function extractCredentialString(credentialEnvelope) {
  if (!credentialEnvelope) return null;
  if (typeof credentialEnvelope === "string") return credentialEnvelope;
  if (typeof credentialEnvelope === "object") {
    console.log("[present] Credential envelope keys:", Object.keys(credentialEnvelope));
    console.log("[present] Credential envelope types:", Object.fromEntries(
      Object.entries(credentialEnvelope).map(([k, v]) => [k, typeof v])
    ));
    // Common OID4VCI response: { credential: "<sd-jwt>" }
    if (typeof credentialEnvelope.credential === "string") return credentialEnvelope.credential;
    // Handle { credentials: { ... } } structure
    if (credentialEnvelope.credentials && typeof credentialEnvelope.credentials === "object") {
      console.log("[present] Found credentials object, keys:", Object.keys(credentialEnvelope.credentials));
      // Look for SD-JWT in credentials object
      for (const [key, value] of Object.entries(credentialEnvelope.credentials)) {
        console.log("[present] credentials[" + key + "] type:", typeof value, "value preview:", typeof value === "string" ? value.substring(0, 100) : JSON.stringify(value).substring(0, 100));
        if (typeof value === "string" && (value.includes("~") || value.split(".").length >= 3)) {
          console.log("[present] Found token in credentials." + key);
          return value;
        }
        // If it's an object, look deeper
        if (typeof value === "object" && value !== null) {
          console.log("[present] credentials[" + key + "] object keys:", Object.keys(value));
          for (const [subKey, subValue] of Object.entries(value)) {
            if (typeof subValue === "string" && (subValue.includes("~") || subValue.split(".").length >= 3)) {
              console.log("[present] Found token in credentials." + key + "." + subKey);
              return subValue;
            }
          }
        }
      }
    }
    // Try to find first string value that looks like token
    for (const v of Object.values(credentialEnvelope)) {
      if (typeof v === "string" && (v.includes("~") || v.split(".").length >= 3)) return v;
    }
  }
  return null;
}

export async function performPresentation({ deepLink, verifierBase, credentialType, keyPath }, logSessionId) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
  const { requestUri, clientId, method } = parseOpenId4VpDeepLink(deepLink);
  try { slog("[present] parsed deepLink", { requestUri, clientId, method }); } catch {}
  const requestJwt = await fetchAuthorizationRequestJwt(requestUri, method);
  const { payload } = decodeJwt(requestJwt);

  const responseMode = payload.response_mode || "direct_post";
  const responseUri = payload.response_uri; // our routes embed this
  const nonce = payload.nonce;
  const state = payload.state;
  const presentationDefinition = payload.presentation_definition;
  console.log("[present] Request payload summary →", { responseMode, hasResponseUri: !!responseUri, hasNonce: !!nonce, hasPD: !!presentationDefinition, state });
  try { slog("[present] request payload", { responseMode, hasResponseUri: !!responseUri, hasNonce: !!nonce, hasPD: !!presentationDefinition, state }); } catch {}

  if (!responseUri) throw new Error("Missing response_uri in request");
  if (!nonce) throw new Error("Missing nonce in request");

  // Determine which wallet credential to use
  let selectedType = credentialType;
  if (!selectedType) {
    // Try to infer from presentation_definition (dcql vct or descriptor id hints)
    const candidateTypes = await listWalletCredentialTypes(); try { slog("[present] wallet types", { count: candidateTypes.length }); } catch {}
    console.log("[present] Available wallet credential types:", candidateTypes);
    if (candidateTypes.length === 0) throw new Error("No credentials available in wallet cache");
    // Heuristic: prefer a candidate whose type name appears in definition id/descriptor ids
    const defText = JSON.stringify(presentationDefinition || {});
    selectedType = candidateTypes.find((t) => defText.includes(t)) || candidateTypes[0];
  }
  console.log("[present] Selected credential type:", selectedType); try { slog("[present] selected type", { selectedType }); } catch {}

  const stored = await getWalletCredentialByType(selectedType);
  console.log("[present] Stored credential found:", !!stored, "has.credential=", !!stored?.credential); try { slog("[present] stored credential", { found: !!stored, hasCredential: !!stored?.credential }); } catch {}
  if (!stored || !stored.credential) throw new Error("Credential not found in wallet cache");

  // Build key-binding JWT
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath || undefined);
  const didJwk = generateDidJwkFromPrivateJwk(publicJwk);
  const kbJwt = await createProofJwt({ privateJwk, publicJwk, audience: verifierBase || clientId || responseUri, nonce, issuer: didJwk });
  console.log("[present] Built kbJwt len:", kbJwt.length); try { slog("[present] kbJwt created", { length: kbJwt.length }); } catch {}

  // Debug: decode kbJwt to verify nonce
  try {
    const kbPayload = decodeJwt(kbJwt).payload;
    console.log("[present] kbJwt payload nonce:", kbPayload.nonce, "expected:", nonce); try { slog("[present] kbJwt payload", { hasNonce: !!kbPayload?.nonce }); } catch {}
  } catch (e) {
    console.log("[present] Could not decode kbJwt for debugging:", e.message); try { slog("[present] kbJwt decode failed", { error: e?.message || String(e) }); } catch {}
  }

  let vpToken = extractCredentialString(stored.credential);
  console.log("[present] Extracted credential string present=", typeof vpToken === "string", vpToken ? (vpToken.includes("~") ? "sd-jwt" : "jwt/other") : "none"); try { slog("[present] token extracted", { present: !!vpToken }); } catch {}
  if (!vpToken) throw new Error("Unable to extract presentable credential token from wallet cache");

  // For SD-JWT, ensure the key-binding JWT is appended if missing
  if (typeof vpToken === "string" && vpToken.includes("~")) {
    const before = vpToken;
    vpToken = attachKbJwtToSdJwt(vpToken, kbJwt);
    if (before !== vpToken) { console.log("[present] Appended kbJwt to SD-JWT"); try { slog("[present] kbJwt appended"); } catch {} }
    else { console.log("[present] SD-JWT already had kbJwt attached"); try { slog("[present] kbJwt already attached"); } catch {} }
  } else {
    // For non-SD-JWT, we might need to create a VP wrapper
    console.log("[present] Non-SD-JWT token, using as-is"); try { slog("[present] non-sd-jwt token"); } catch {}
  }

  const presentation_submission = buildPresentationSubmission(presentationDefinition);
  if (presentation_submission) { console.log("[present] Built presentation_submission len:", presentation_submission.length); try { slog("[present] submission built", { length: presentation_submission.length }); } catch {} }

  // Send the raw SD-JWT token directly - the verifier expects the actual token, not a VP wrapper
  let body;
  if (presentation_submission) {
    // Use presentation_submission format with raw SD-JWT
    body = {
      vp_token: vpToken, // Send the raw SD-JWT token
      presentation_submission, // Send as JSON string (as expected by verifier)
      ...(state ? { state } : {}),
    };
    console.log("[present] Using raw SD-JWT with presentation_submission format"); try { slog("[present] using submission format"); } catch {}
  } else {
    // Direct format with raw SD-JWT
    body = {
      vp_token: vpToken, // Send the raw SD-JWT token
      ...(state ? { state } : {}),
    };
    console.log("[present] Using raw SD-JWT with direct format"); try { slog("[present] using direct format"); } catch {}
  }
  console.log("[present] Posting to response_uri:", responseUri, "body.keys=", Object.keys(body)); try { slog("[present] posting", { responseUri, keys: Object.keys(body) }); } catch {}

  const res = await fetch(responseUri, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const resText = await res.text().catch(() => "");
  console.log("[present] Verifier response status:", res.status, "body.len=", resText?.length); try { slog("[present] verifier response", { status: res.status, bodyLen: resText?.length }); } catch {}
  console.log("[present] Sent vp_token preview:", vpToken.substring(0, 200) + "...");
  console.log("[present] Sent presentation_submission:", presentation_submission);
  console.log("[present] presentation_submission type:", typeof presentation_submission);
  console.log("[present] Full request body:", JSON.stringify(body, null, 2));
  if (!res.ok) {
    let parsed = null;
    try { parsed = JSON.parse(resText); } catch {}
    throw new Error(`Verifier response error ${res.status}${parsed ? ": " + JSON.stringify(parsed) : resText ? ": " + resText.slice(0, 500) : ""}`);
  }
  try { return JSON.parse(resText); } catch { return { status: "ok" }; }
}

export async function resolveDeepLinkFromEndpoint(verifierBase, path) {
  const url = new URL((verifierBase || "http://localhost:3000").replace(/\/$/, "") + path);
  console.log("[present] Resolving deepLink from:", url.toString());
  const res = await fetch(url.toString());
  if (!res.ok) throw new Error(`Fetch VP request error ${res.status}`);
  const body = await res.json();
  // Expect { deepLink } shape
  if (body.deepLink) return body.deepLink;
  // Some endpoints return { request: jwt } or raw JWT; build openid4vp link ourselves if needed
  if (body.request) {
    // No request_uri; not supported here
    throw new Error("Received inline request JWT; provide openid4vp deep link instead");
  }
  throw new Error("Unexpected response from verifier when fetching VP request");
}


