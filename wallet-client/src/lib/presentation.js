import fetch from "node-fetch";
import { createProofJwt, generateDidJwkFromPrivateJwk, ensureOrCreateEcKeyPair } from "./crypto.js";
import { getWalletCredentialByType, listWalletCredentialTypes, appendWalletLog } from "./cache.js";
import { buildMdocPresentation, isMdocCredential } from "../../utils/mdlVerification.js";

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

function buildPresentationSubmission(presentationDefinition, credentialFormat) {
  if (!presentationDefinition) return undefined;
  console.log("[present] Building presentation_submission from definition:", presentationDefinition.id);
  console.log("[present] Input descriptors:", presentationDefinition.input_descriptors?.length || 0);

  const inputDescriptors = presentationDefinition.input_descriptors || [];
  const format = credentialFormat || inferRootFormat(presentationDefinition);
  const descriptorMap = inputDescriptors.map((d) => ({ id: d.id, format, path: "$.vp_token" }));

  console.log("[present] Descriptor map:", JSON.stringify(descriptorMap, null, 2));

  // The verifier expects JSON string in some handlers; keep as string to be safe
  const submission = { definition_id: presentationDefinition.id || "pd", descriptor_map: descriptorMap };
  console.log("[present] Built presentation_submission:", JSON.stringify(submission, null, 2));
  return JSON.stringify(submission);
}

function inferRootFormat(presentationDefinition) {
  // Infer format from presentation definition
  const fmt = presentationDefinition.format || {};
  if (fmt["mso_mdoc"]) return "mso_mdoc"; // mdoc format
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
      // Look for SD-JWT, JWT, or mdoc in credentials object
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
            if (typeof subValue === "string") {
              // Check for SD-JWT, JWT, or mdoc (base64 string)
              if (subValue.includes("~") || subValue.split(".").length >= 3 || isMdocCredential(subValue)) {
                console.log("[present] Found token in credentials." + key + "." + subKey);
                return subValue;
              }
            }
          }
        }
      }
    }
    // Try to find first string value that looks like token
    for (const v of Object.values(credentialEnvelope)) {
      if (typeof v === "string" && (v.includes("~") || v.split(".").length >= 3 || isMdocCredential(v))) return v;
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

  let responseMode = payload.response_mode || "direct_post";
  const responseUri = payload.response_uri; // our routes embed this
  // If the response_uri suggests direct_post.jwt, force that mode for compatibility
  if (responseUri && /direct_post\.jwt/i.test(responseUri)) {
    console.log("[present] Forcing response_mode to direct_post.jwt based on response_uri");
    responseMode = "direct_post.jwt";
  }
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
  const kbAudience = clientId || responseUri || verifierBase;
  const kbJwt = await createProofJwt({ privateJwk, publicJwk, audience: kbAudience, nonce, issuer: didJwk });
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

  // Check if this is an mdoc credential
  const isMdoc = isMdocCredential(vpToken);
  console.log("[present] Credential type detected:", isMdoc ? "mdoc" : (vpToken.includes("~") ? "sd-jwt" : "jwt")); try { slog("[present] credential type", { isMdoc, isSdJwt: vpToken.includes("~") }); } catch {}

  if (isMdoc) {
    // For mdoc, construct proper DeviceResponse structure
    console.log("[present] Processing mdoc credential for presentation"); try { slog("[present] processing mdoc"); } catch {}
    
    // Determine docType from credential type, presentation definition, or descriptor ID
    let docType = selectedType || "org.iso.18013.5.1.mDL"; // Use selected credential type as default
    
    if (presentationDefinition?.input_descriptors?.[0]?.id) {
      const descriptorId = presentationDefinition.input_descriptors[0].id;
      
      // If descriptor ID looks like a docType (has dots/colons), use it directly
      if (descriptorId.includes('.') || descriptorId.includes(':')) {
        docType = descriptorId;
      }
      // Otherwise, try to infer from known patterns
      else if (descriptorId.includes("pid") || descriptorId.includes("PID")) {
        docType = "eu.europa.ec.eudi.pid.1";
      } else if (descriptorId.includes("mdl") || descriptorId.includes("mDL")) {
        docType = "org.iso.18013.5.1.mDL";
      }
    }
    
    console.log("[present] Using docType:", docType, "from selectedType:", selectedType); try { slog("[present] docType", { docType, selectedType }); } catch {}
    
    // Build proper DeviceResponse for presentation
    vpToken = await buildMdocPresentation(vpToken, { docType });
    console.log("[present] Built DeviceResponse, length:", vpToken.length); try { slog("[present] DeviceResponse built", { length: vpToken.length }); } catch {}
  } else if (typeof vpToken === "string" && vpToken.includes("~")) {
    // For SD-JWT, ensure the key-binding JWT is appended if missing
    const before = vpToken;
    vpToken = attachKbJwtToSdJwt(vpToken, kbJwt);
    if (before !== vpToken) { console.log("[present] Appended kbJwt to SD-JWT"); try { slog("[present] kbJwt appended"); } catch {} }
    else { console.log("[present] SD-JWT already had kbJwt attached"); try { slog("[present] kbJwt already attached"); } catch {} }
  } else {
    // For JWT VC, use as-is
    console.log("[present] JWT VC token, using as-is"); try { slog("[present] jwt-vc token"); } catch {}
  }

  // Determine credential format for presentation_submission
  const credentialFormat = isMdoc ? "mso_mdoc" : (vpToken.includes("~") ? "dc+sd-jwt" : "jwt_vc_json");
  console.log("[present] Credential format for submission:", credentialFormat); try { slog("[present] credential format", { format: credentialFormat }); } catch {}
  
  const presentation_submission = buildPresentationSubmission(presentationDefinition, credentialFormat);
  if (presentation_submission) { console.log("[present] Built presentation_submission len:", presentation_submission.length); try { slog("[present] submission built", { length: presentation_submission.length }); } catch {} }

  // Send the credential token (SD-JWT, mdoc DeviceResponse, or JWT VC)
  // Per OpenID4VP spec:
  // - direct_post: application/x-www-form-urlencoded with vp_token (+ optional presentation_submission)
  // - direct_post.jwt: application/x-www-form-urlencoded with 'response' containing a JWE/JWT
  let body;
  let bodyContent;
  let contentType;
  
  if (presentation_submission) {
    // Use presentation_submission format
    body = {
      vp_token: vpToken,
      presentation_submission, // Send as JSON string (as expected by verifier)
      ...(state ? { state } : {}),
    };
    console.log("[present] Using presentation_submission format"); try { slog("[present] using submission format"); } catch {}
  } else {
    // Direct format
    body = {
      vp_token: vpToken,
      ...(state ? { state } : {}),
    };
    console.log("[present] Using direct format"); try { slog("[present] using direct format"); } catch {}
  }
  
  if ((responseMode || "direct_post") === "direct_post.jwt") {
    // Build a compact JWT payload and encrypt to JWE if verifier provides JWKS
    // Wallet signs nothing here to avoid verifier signature mismatch; use JWE per spec branch in verifier
    let responseJwtOrJwe = null;
    try {
      const clientMetadata = payload.client_metadata || payload.clientMetadata || {};
      const jwks = clientMetadata.jwks || (clientMetadata.jwks_uri ? await (await fetch(clientMetadata.jwks_uri)).json() : null);
      const encKey = jwks?.keys?.find((k) => (k.use === 'enc' || !k.use) && (k.kty === 'EC' || k.kty === 'OKP' || k.kty === 'RSA'));

      // Build signed JWT payload per OpenID4VP direct_post.jwt
      const now = Math.floor(Date.now() / 1000);
      let presentationSubmissionObj = undefined;
      if (presentation_submission) {
        try { presentationSubmissionObj = JSON.parse(presentation_submission); } catch {}
      }
      const jwtPayload = {
        vp_token: vpToken,
        ...(presentationSubmissionObj ? { presentation_submission: presentationSubmissionObj } : {}),
        ...(state ? { state } : {}),
        ...(nonce ? { nonce } : {}),
        iat: now,
        exp: now + 300,
        iss: didJwk,
        // OID4VP direct_post.jwt aligns with JARM: aud SHOULD be the verifier's client_id
        aud: clientId || responseUri
      };

      // Sign with wallet key (ES256)
      const { importJWK, SignJWT, CompactEncrypt, EncryptJWT } = await import('jose');

      if (encKey) {
        // Encrypt to JWE so verifier follows its JWE branch
        
        // Prioritize encryption settings from client_metadata
        let alg = clientMetadata.authorization_encrypted_response_alg || encKey.alg || 'ECDH-ES+A256KW';
        if (alg === 'ECDH-ES') alg = 'ECDH-ES+A256KW'; // Ensure key wrapping alg is included

        let enc = 'A256GCM'; // Default enc
        if (clientMetadata.authorization_encrypted_response_enc) {
          enc = clientMetadata.authorization_encrypted_response_enc;
        } else if (Array.isArray(clientMetadata.encrypted_response_enc_values_supported)) {
          const supportedEnc = clientMetadata.encrypted_response_enc_values_supported;
          const preferredEnc = supportedEnc.find((e) => ['A256GCM','A192GCM','A128GCM','A256CBC-HS512','A192CBC-HS384','A128CBC-HS256'].includes(e));
          if (preferredEnc) enc = preferredEnc;
        }

        const publicKey = await importJWK(encKey, alg.startsWith('ECDH-ES') ? 'ECDH-ES' : undefined);
        const jweProtectedHeader = { alg, enc, kid: encKey.kid };
        console.log('[present] JWE protected header:', jweProtectedHeader);

        // OID4VP-15: "The Authorization Response is returned as a JSON object, which MUST be encrypted as the payload of a JWE"
        // Encrypt the JSON payload directly, not a nested signed JWT.
        responseJwtOrJwe = await new EncryptJWT(jwtPayload)
          .setProtectedHeader(jweProtectedHeader)
          .encrypt(publicKey);

        console.log('[present] Created JWE:', responseJwtOrJwe.substring(0, 100) + '...');
      } else {
        // Fallback: send signed JWT directly if no enc key is provided
        const signingKey = await importJWK(privateJwk, 'ES256');
        responseJwtOrJwe = await new SignJWT(jwtPayload)
          .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: didJwk })
          .setIssuer(jwtPayload.iss)
          .setAudience(jwtPayload.aud)
          .setIssuedAt(jwtPayload.iat)
          .setExpirationTime(jwtPayload.exp)
          .sign(signingKey);
      }

      const formParams = new URLSearchParams();
      formParams.append('response', responseJwtOrJwe);
      if (state) formParams.append('state', state);
      bodyContent = formParams.toString();
      contentType = 'application/x-www-form-urlencoded';
    } catch (e) {
      console.log('[present] Failed to build direct_post.jwt response, falling back to direct_post:', e.message);
    }
  }
  
  if (!bodyContent) {
    // Default: direct_post
    const formParams = new URLSearchParams();
    formParams.append("vp_token", vpToken);
    if (presentation_submission) {
      formParams.append("presentation_submission", presentation_submission);
    }
    if (state) {
      formParams.append("state", state);
    }
    bodyContent = formParams.toString();
    contentType = "application/x-www-form-urlencoded";
  }
  
  console.log("[present] Posting to response_uri:", responseUri, "body.keys=", Object.keys(body)); try { slog("[present] posting", { responseUri, keys: Object.keys(body) }); } catch {}

  const res = await fetch(responseUri, {
    method: "POST",
    headers: { "content-type": contentType },
    body: bodyContent,
  });
  const resText = await res.text().catch(() => "");
  console.log("[present] Verifier response status:", res.status, "body.len=", resText?.length); try { slog("[present] verifier response", { status: res.status, bodyLen: resText?.length }); } catch {}
  console.log("[present] Sent vp_token preview:", vpToken.substring(0, 200) + "...");
  console.log("[present] Sent presentation_submission:", presentation_submission);
  console.log("[present] presentation_submission type:", typeof presentation_submission);
  console.log("[present] Full request body:", JSON.stringify(body, null, 2));
  if (!res.ok) {
    // Compatibility fallback for some verifiers expecting JWE payload object instead of JWT inside direct_post.jwt
    
    if ((responseMode || "direct_post") === "direct_post.jwt") {
      try {
        console.log("[present] direct_post.jwt failed (" + res.status + ") – retrying with payload-object JWE fallback");
        const clientMetadata = payload.client_metadata || payload.clientMetadata || {};
        const jwks = clientMetadata.jwks || (clientMetadata.jwks_uri ? await (await fetch(clientMetadata.jwks_uri)).json() : null);
        const encKey = jwks?.keys?.find((k) => (k.use === 'enc' || !k.use) && (k.kty === 'EC' || k.kty === 'OKP' || k.kty === 'RSA'));
        if (encKey) {
          const { importJWK, EncryptJWT } = await import('jose');
          const alg = encKey.alg || 'ECDH-ES+A256KW';
          const supportedEnc = Array.isArray(clientMetadata.encrypted_response_enc_values_supported)
            ? clientMetadata.encrypted_response_enc_values_supported
            : [];
          const preferredEnc = supportedEnc.find((e) => ['A256GCM','A192GCM','A128GCM','A256CBC-HS512','A192CBC-HS384','A128CBC-HS256'].includes(e));
          const enc = preferredEnc || 'A256GCM';
          const publicKey = await importJWK(encKey, alg.startsWith('ECDH-ES') ? 'ECDH-ES' : undefined);
          const fallbackPayload = { vp_token: vpToken, ...(presentation_submission ? { presentation_submission: JSON.parse(presentation_submission) } : {}), ...(state ? { state } : {}) };
          // Build a JWE with JSON payload (so jwtDecrypt returns { payload })
          const jwe = await new EncryptJWT(fallbackPayload)
            .setProtectedHeader({ alg, enc, kid: encKey.kid })
            .encrypt(publicKey);
          const formParams2 = new URLSearchParams();
          formParams2.append('response', jwe);
          const res2 = await fetch(responseUri, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: formParams2.toString() });
          const res2Text = await res2.text().catch(() => "");
          console.log("[present] Fallback verifier response status:", res2.status, "body.len=", res2Text?.length);
          if (!res2.ok) {
            let parsed2 = null;
            try { parsed2 = JSON.parse(res2Text); } catch {}
            throw new Error(`Verifier response error ${res2.status}${parsed2 ? ": " + JSON.stringify(parsed2) : res2Text ? ": " + res2Text.slice(0, 500) : ""}`);
          }
          try { return JSON.parse(res2Text); } catch { return { status: "ok" }; }
        }
      } catch (e) {
        console.log("[present] Fallback attempt failed:", e?.message || String(e));
      }
    }
    
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


