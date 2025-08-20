#!/usr/bin/env node
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import fetch from "node-fetch";
import { createProofJwt, generateDidJwkFromPrivateJwk, ensureOrCreateEcKeyPair } from "./lib/crypto.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const argv = yargs(hideBin(process.argv))
    .option("issuer", { type: "string", default: "http://localhost:3000" })
    .option("offer", { type: "string", describe: "openid-credential-offer deep link" })
    .option("fetch-offer", { type: "string", describe: "issuer path to fetch an offer, e.g. /offer-no-code" })
    .option("credential", { type: "string", describe: "credential_configuration_id to request" })
    .option("key", { type: "string", describe: "path to EC P-256 private JWK file" })
    .option("poll-interval", { type: "number", default: 2000 })
    .option("poll-timeout", { type: "number", default: 30000 })
    .strict()
    .help()
    .parse();

  const issuerBase = argv.issuer.replace(/\/$/, "");

  const deepLink = argv.offer || (await getOfferDeepLink(issuerBase, argv["fetch-offer"], argv.credential));
  if (!deepLink) {
    console.error("No offer provided or fetched.");
    process.exit(1);
  }

  const offerConfig = await resolveOfferConfig(deepLink);
  const { credential_issuer, credential_configuration_ids, grants } = offerConfig;

  const configurationId = argv.credential || credential_configuration_ids?.[0];
  if (!configurationId) {
    console.error("No credential_configuration_id available in offer; use --credential");
    process.exit(1);
  }

  const preAuthGrant = grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
  if (!preAuthGrant) {
    console.error("Only pre-authorized_code is supported in this client.");
    process.exit(1);
  }

  const preAuthorizedCode = preAuthGrant["pre-authorized_code"]; // sessionId
  const txCode = preAuthGrant?.tx_code ? await promptTxCode(preAuthGrant.tx_code) : undefined;

  const tokenEndpoint = `${issuerBase}/token_endpoint`;
  const tokenRes = await httpPostJson(tokenEndpoint, {
    grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": preAuthorizedCode,
    ...(txCode ? { tx_code: txCode } : {}),
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.json().catch(() => ({}));
    throw new Error(`Token error ${tokenRes.status}: ${JSON.stringify(err)}`);
  }
  const tokenBody = await tokenRes.json();
  const accessToken = tokenBody.access_token;

  // get c_nonce from nonce endpoint
  const nonceEndpoint = `${issuerBase}/nonce`;
  const nonceRes = await httpPostJson(nonceEndpoint, {});
  if (!nonceRes.ok) {
    const err = await nonceRes.json().catch(() => ({}));
    throw new Error(`Nonce error ${nonceRes.status}: ${JSON.stringify(err)}`);
  }
  const { c_nonce } = await nonceRes.json();

  // key management
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(argv.key);
  const didJwk = generateDidJwkFromPrivateJwk(publicJwk);

  // build proof JWT
  const proofJwt = await createProofJwt({
    privateJwk,
    publicJwk,
    audience: issuerBase,
    nonce: c_nonce,
    issuer: didJwk,
  });

  // credential request
  const credentialEndpoint = `${issuerBase}/credential`;
  const credReq = {
    credential_configuration_id: configurationId,
    proof: { proof_type: "jwt", jwt: proofJwt },
  };

  const credRes = await fetch(credentialEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(credReq),
  });

  if (credRes.status === 202) {
    const { transaction_id } = await credRes.json();
    const start = Date.now();
    while (Date.now() - start < argv["poll-timeout"]) {
      await sleep(argv["poll-interval"]);
      const defRes = await httpPostJson(`${issuerBase}/credential_deferred`, { transaction_id });
      if (defRes.ok) {
        const body = await defRes.json();
        console.log(JSON.stringify(body, null, 2));
        return;
      }
    }
    throw new Error("Deferred issuance timed out");
  }

  if (!credRes.ok) {
    const err = await credRes.json().catch(() => ({}));
    throw new Error(`Credential error ${credRes.status}: ${JSON.stringify(err)}`);
  }

  const credBody = await credRes.json();
  console.log(JSON.stringify(credBody, null, 2));
}

async function getOfferDeepLink(issuerBase, path, credentialType) {
  if (!path) return undefined;
  const url = new URL(issuerBase + path);
  if (credentialType) url.searchParams.set("type", credentialType);
  const res = await fetch(url.toString());
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Fetch-offer error ${res.status}: ${JSON.stringify(err)}`);
  }
  const body = await res.json();
  return body.deepLink;
}

async function resolveOfferConfig(deepLink) {
  const url = new URL(deepLink.replace(/^haip:\/\//, "openid-credential-offer://"));
  if (url.protocol !== "openid-credential-offer:") {
    throw new Error("Unsupported offer scheme");
  }
  const encoded = url.searchParams.get("credential_offer_uri");
  if (!encoded) throw new Error("Missing credential_offer_uri in offer");
  const offerUri = decodeURIComponent(encoded);
  const res = await fetch(offerUri);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Offer-config error ${res.status}: ${JSON.stringify(err)}`);
  }
  return res.json();
}

async function promptTxCode(cfg) {
  // Non-interactive default: generate a dummy numeric code if required; issuer currently does not validate tx_code server-side.
  if (cfg?.input_mode === "numeric" && typeof cfg?.length === "number") {
    return "".padStart(cfg.length, "1");
  }
  return undefined;
}

async function httpPostJson(url, body) {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});


