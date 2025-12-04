import crypto from "crypto";
import jwt from "jsonwebtoken";
import * as jose from "jose";
import base64url from "base64url";
import { error } from "console";
import fs from "fs";
import { generateRefreshToken } from "./tokenUtils.js";
import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import fetch from "node-fetch";

export function pemToJWK(pem, keyType) {
  let key;
  let jwk;

  if (keyType === "private") {
    key = crypto.createPrivateKey(pem);
    // Export JWK including the private key parameter (`d`)
    jwk = key.export({ format: "jwk" }); // This includes x, y, and d for EC keys
  } else {
    key = crypto.createPublicKey(pem);
    // Export JWK with only public components
    jwk = key.export({ format: "jwk" }); // This includes x and y for EC keys
  }

  // Optionally, set or adjust JWK properties if necessary
  jwk.kty = "EC"; // Key Type
  jwk.crv = "P-256"; //"P-384"; // Curve (adjust as necessary based on your actual curve)

  return jwk;
}

export function generateNonce(length = 12) {
  return crypto.randomBytes(length).toString("hex");
}

export function buildVpRequestJSON(
  state,
  nonce,
  client_id,
  response_uri,
  presentation_definition,
  jwk,
  serverURL,
  privateKey
) {
  /*
      client_id	Verifier identifier for .e.g URI / DID. This value must be present in sub field of the verifiable presentation JWT
      response_type	The value must be vp_token
      scope	Optional value, details are specified in [Section 3.1.1](#3.1.1-scope-parameter-usage)
      response_uri	This should be present when the response_mode is direct_post.
      response_mode	The value must be direct_post
      state	The client uses an opaque value to maintain the state between the request and callback.
      nonce	Securely bin verifiable presentations provided by the wallet to a particular transaction
      presentation_definition	The verifier requires proof. It must conform to the DIF Presentation Exchange specification [4].
*/

  /**
 Location: https://client.example.org/universal-link?
    response_type=vp_token
    &client_id=https%3A%2F%2Fclient.example.org%2Fcb
    &client_id_scheme=redirect_uri
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &presentation_definition=...
    &nonce=n-0S6_WzA2Mj
    &client_metadata=%7B%22vp_formats%22:%7B%22jwt_vp%22:%
    7B%22alg%22:%5B%22EdDSA%22,%22ES256K%22%5D%7D,%22ldp
    _vp%22:%7B%22proof_type%22:%5B%22Ed25519Signature201
    8%22%5D%7D%7D%7D
 * 
 */

  let jwtPayload = {
    response_type: "vp_token",
    client_id: client_id,
    client_id_scheme: "redirect_uri",
    presentation_definition: presentation_definition,
    redirect_uri: response_uri,
    // response_mode: "direct_post",
    nonce: "n-0S6_WzA2Mj",
    state: "af0ifjsldkj",
    client_metadata: {
      vp_formats: {
        "vc+sd-jwt": {
          "sd-jwt_alg_values": ["ES256", "ES384"],
          "kb-jwt_alg_values": ["ES256", "ES384"],
        },
        ldp_vp: {
          proof_type: ["Ed25519Signature2018"],
        },
      },
      // Add any additional required metadata here
    },

    // response_uri: response_uri, //TODO Note: If the Client Identifier scheme redirect_uri is used in conjunction with the Response Mode direct_post, and the response_uri parameter is present, the client_id value MUST be equal to the response_uri value
  };

  // const header = {
  //   alg: "ES256",
  //   kid: `aegean#authentication-key`, //this kid needs to be resolvable from the did.json endpoint
  // };

  // const token = jwt.sign(jwtPayload, privateKey, {
  //   algorithm: "ES256",
  //   noTimestamp: true,
  //   header,
  // });
  return jwtPayload;
}

// Generate a test VA-JWT for development/testing purposes
// NOTE: In production, VA-JWT should be obtained from a trusted third-party issuer
// This self-signed implementation is for testing only and violates the spec requirement
// that VA-JWTs must be issued by a trusted party separate from the verifier
async function generateTestVAJWT(subject) {
  const now = Math.floor(Date.now() / 1000);

  // Load the x509 private key to create a self-signed VA-JWT
  // NOTE: This violates the spec - VA-JWT should be signed by a trusted issuer's key
  const privateKeyPem = fs.readFileSync(
    "./x509/client_private_pkcs8.key",
    "utf8"
  );
  const publicKey = crypto.createPublicKey(privateKeyPem);
  const jwk = publicKey.export({ format: "jwk" });

  const vaHeader = {
    alg: "RS256",
    typ: "verifier-attestation+jwt",
  };

  const vaPayload = {
    iss: "https://dss.aegean.gr", // Self-issued for testing
    sub: subject,
    exp: now + 3600, // 1 hour
    iat: now,
    cnf: { jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e } }, // Public key for proof-of-possession
  };

  const vaJwt = await new jose.SignJWT(vaPayload)
    .setProtectedHeader(vaHeader)
    .sign(await jose.importPKCS8(privateKeyPem, "RS256"));

  return vaJwt;
}

export async function buildVpRequestJWT(
  client_id,
  redirect_uri,
  presentation_definition,
  privateKey = null, // Only used for verifier_attestation scheme proof-of-possession
  client_metadata = {},
  kid = null, // Default to an empty object,
  serverURL,
  response_type = "vp_token",
  nonce,
  dcql_query = null,
  transaction_data = null,
  response_mode = "direct_post", // Add response_mode parameter with default
  audience = "https://self-issued.me/v2", // New audience parameter
  wallet_nonce = null,
  wallet_metadata = null,
  va_jwt = null, // Optional Verifier Attestation JWT for verifier_attestation scheme
  state = null // Add state parameter (last param to match test ordering)
) {
  if (!nonce) nonce = generateNonce(16);
  if (!state) {
    // State is REQUIRED for direct_post modes per OpenID4VP spec
    // Generate only if not provided to maintain backwards compatibility with tests
    state = generateNonce(16);
    console.warn(
      "WARNING: state parameter not provided to buildVpRequestJWT, generating random state. This should be explicitly provided."
    );
  }

  // Validate response_mode
  const allowedResponseModes = [
    "direct_post",
    "direct_post.jwt",
    "dc_api.jwt",
    "dc_api",
  ];
  if (!allowedResponseModes.includes(response_mode)) {
    throw new Error(
      `Invalid response_mode. Must be one of: ${allowedResponseModes.join(
        ", "
      )}`
    );
  }

  // Note: encryption metadata should be provided in client_metadata from verifier-config.json
  // The verifier-config.json should contain jwks and encrypted_response_enc_values_supported

  // Determine client scheme and effective identifier
  const schemeSeparatorIdx = client_id.indexOf(":");
  const schemePrefix =
    schemeSeparatorIdx > 0 ? client_id.substring(0, schemeSeparatorIdx) : null;
  const isRedirectUriScheme = schemePrefix === "redirect_uri";
  const isDecentralizedIdScheme = schemePrefix === "decentralized_identifier";
  const effectiveClientId = isDecentralizedIdScheme
    ? client_id.substring("decentralized_identifier:".length)
    : isRedirectUriScheme
    ? client_id.substring("redirect_uri:".length)
    : client_id;

  // Construct the JWT payload
  let jwtPayload = {
    response_type: response_type,
    response_mode: response_mode,
    client_id: client_id,

    nonce: nonce,
    state: state,
    // For redirect_uri scheme, client_metadata MUST be omitted (wallet discovers metadata)
    ...(isRedirectUriScheme ? {} : { client_metadata: client_metadata }),
    // NOTE: Per OpenID4VP, wallets MUST ignore an iss claim in the authorization request.
    // To avoid confusion for implementers, we intentionally omit iss here.
    aud: audience, // Use the audience parameter
  };

  // Add response_uri for all response modes that require it
  if (
    response_mode === "direct_post" ||
    response_mode === "direct_post.jwt" ||
    response_mode === "dc_api.jwt" ||
    response_mode === "dc_api"
  ) {
    jwtPayload.response_uri = redirect_uri;
  }

  // Set appropriate audience based on response mode
  if (response_mode === "dc_api.jwt" || response_mode === "dc_api") {
    jwtPayload.aud = "https://self-issued.me/v2"; // Digital Credentials API audience
  } else {
    jwtPayload.aud = client_id; // For direct_post, audience should be the client_id
  }

  // Add required timestamp claims for Digital Credentials API
  if (response_mode === "dc_api.jwt" || response_mode === "dc_api") {
    const now = Math.floor(Date.now() / 1000);
    jwtPayload.iat = now; // issued at time
    jwtPayload.exp = now + 60 * 60; // expires in 1 hour
    jwtPayload.expected_origins = ["https://dss.aegean.gr"];
    jwtPayload.state = state;
  }

  const now = Math.floor(Date.now() / 1000);
  jwtPayload.iat = now; // issued at time
  jwtPayload.exp = now + 60 * 5; // expires in 5 minutes

  // console.log("wallet_nonce", wallet_nonce);
  if (wallet_nonce) jwtPayload.wallet_nonce = wallet_nonce;

  // OpenID4VP v1.0: Only DCQL is supported; PEX (presentation_definition) is not supported
  if (presentation_definition) {
    throw new Error(
      "Presentation Exchange (presentation_definition) is not supported; use dcql_query per OpenID4VP 1.0"
    );
  }

  // Add dcql_query if provided (required in place of PEX)
  if (dcql_query) {
    jwtPayload.dcql_query = dcql_query;
  }

  // Add transaction_data if provided
  if (transaction_data) {
    jwtPayload.transaction_data = transaction_data;
  }

  let signedJwt;

  if (response_mode === "dc_api.jwt" || response_mode === "dc_api") {
    // Use EC certificates for Digital Credentials API
    privateKey = fs.readFileSync("./x509EC/ec_private_pkcs8.key", "utf8");
    const certificate = fs.readFileSync(
      "./x509EC/client_certificate.crt",
      "utf8"
    );
    // Convert certificate to Base64 without headers
    const certBase64 = certificate
      .replace("-----BEGIN CERTIFICATE-----", "")
      .replace("-----END CERTIFICATE-----", "")
      .replace(/\s+/g, "");

    const header = {
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      x5c: [certBase64],
    };

    signedJwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, "ES256"));
  } else if (
    effectiveClientId.startsWith("x509_san_dns:") ||
    effectiveClientId.startsWith("x509_san_uri:")
  ) {
    privateKey = fs.readFileSync("./x509/client_private_pkcs8.key", "utf8");
    const certificate = fs.readFileSync(
      "./x509/client_certificate.crt",
      "utf8"
    );
    // Convert certificate to Base64 without headers
    const certBase64 = certificate
      .replace("-----BEGIN CERTIFICATE-----", "")
      .replace("-----END CERTIFICATE-----", "")
      .replace(/\s+/g, "");

    const header = {
      alg: "RS256",
      typ: "oauth-authz-req+jwt",
      x5c: [certBase64],
    };

    signedJwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, "RS256"));
  } else if (effectiveClientId.startsWith("x509_hash:")) {
    privateKey = fs.readFileSync("./x509/client_private_pkcs8.key", "utf8");
    const certificate = fs.readFileSync(
      "./x509/client_certificate.crt",
      "utf8"
    );
    // Compute Base64URL-encoded SHA-256 of leaf cert (DER)
    const certBase64 = certificate
      .replace("-----BEGIN CERTIFICATE-----", "")
      .replace("-----END CERTIFICATE-----", "")
      .replace(/\s+/g, "");
    const certDer = Buffer.from(certBase64, "base64");
    const hash = crypto.createHash("sha256").update(certDer).digest();
    const hashB64Url = base64url.encode(hash);
    const expectedClientId = `x509_hash:${hashB64Url}`;
    if (client_id !== expectedClientId) {
      throw new Error(
        `x509_hash client_id mismatch: expected ${expectedClientId} but got ${client_id}`
      );
    }

    const header = {
      alg: "RS256",
      typ: "oauth-authz-req+jwt",
      x5c: [certBase64],
    };

    signedJwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, "RS256"));
  } else if (effectiveClientId.startsWith("did:")) {
    // Check if this is a did:jwk identifier
    if (effectiveClientId.startsWith("did:jwk:")) {
      // Load private key from file for DID JWK
      const didJwkPrivateKey = fs.readFileSync(
        "./didjwks/did_private_pkcs8.key",
        "utf8"
      );

      const header = {
        alg: "ES256",
        typ: "oauth-authz-req+jwt",
        kid: kid, // This will be in the format did:jwk:<base64url-encoded-jwk>#0
      };

      signedJwt = await new jose.SignJWT(jwtPayload)
        .setProtectedHeader(header)
        .sign(await jose.importPKCS8(didJwkPrivateKey, "ES256"));
    } else if (effectiveClientId.startsWith("did:web:")) {
      // Handle did:web case - load private key from file
      const didWebPrivateKey = fs.readFileSync(
        "./didjwks/did_private_pkcs8.key",
        "utf8"
      );

      const signingKey = {
        kty: "EC",
        x: "ijVgOGHvwHSeV1Z2iLF9pQLQAw7KcHF3VIjThhvVtBQ",
        y: "SfFShWAUGEnNx24V2b5G1jrhJNHmMwtgROBOi9OKJLc",
        crv: "P-256",
        use: "sig",
        kid: kid,
      };

      // Convert the private key to a KeyLike object
      const privateKeyObj = await jose.importPKCS8(
        didWebPrivateKey,
        signingKey.alg || "ES256"
      );

      // JWT header
      const header = {
        alg: signingKey.alg || "ES256",
        typ: "oauth-authz-req+jwt",
        kid: kid,
      };

      signedJwt = await new jose.SignJWT(jwtPayload)
        .setProtectedHeader(header)
        .sign(privateKeyObj);
    } else {
      throw new Error("Unsupported DID method: " + client_id);
    }
  } else {
    // For redirect_uri scheme, unsigned JAR is allowed; still sign with default if private key available
    if (isRedirectUriScheme) {
      const header = {
        alg: "none",
        typ: "oauth-authz-req+jwt",
      };
      // Produce unsecured JWT (JWS with alg=none) if signing key not applicable
      signedJwt = `${base64url.encode(
        JSON.stringify(header)
      )}.${base64url.encode(JSON.stringify(jwtPayload))}.`;
    } else if (schemePrefix === "verifier_attestation") {
      // Use provided VA-JWT or generate one for development/testing
      const nonPrefixedId = client_id.substring('verifier_attestation:'.length);
      if (!va_jwt) {
        va_jwt = await generateTestVAJWT(nonPrefixedId);
      }

      const parts = va_jwt.split('.');
      let vaPayload;
      try {
        vaPayload = JSON.parse(base64url.decode(parts[1]));
      } catch (e) {
        throw new Error("Invalid VA-JWT payload format");
      }

      // Validate sub matches non-prefixed client identifier (VP 1.0 spec requirement)
      if (vaPayload.sub !== nonPrefixedId) {
        throw new Error("VA-JWT sub does not match non-prefixed client_id");
      }

      // For verifier attestation, use the same x509 private key as other x509 schemes
      // this is the same key as the one used in the cnf claim of the va_jwt
      privateKey = fs.readFileSync("./x509/client_private_pkcs8.key", "utf8");
      const certificate = fs.readFileSync(
        "./x509/client_certificate.crt",
        "utf8"
      );

      // Convert certificate to Base64 without headers
      const certBase64 = certificate
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace(/\s+/g, "");

      // Include VA-JWT in JOSE header as 'jwt' (VP 1.0 spec requirement)
      const header = {
        alg: "RS256",
        typ: "oauth-authz-req+jwt",
        x5c: [certBase64],
        jwt: va_jwt, // Verifier Attestation JWT in JOSE header
      };

      signedJwt = await new jose.SignJWT(jwtPayload)
        .setProtectedHeader(header)
        .sign(await jose.importPKCS8(privateKey, "RS256"));
    } else {
      throw new Error(
        "not supported client_id scheme for client_id:" + client_id
      );
    }
  }

  // If wallet_metadata with jwks is provided, encrypt the request object
  if (wallet_metadata && wallet_metadata.jwks) {
    console.log(
      "Encrypting request object using wallet's public key from wallet_metadata."
    );

    const jwks = wallet_metadata.jwks;
    // Find a key suitable for encryption
    const encryptionKey = jwks.keys.find(
      (k) => k.use === "enc" || k.use === undefined
    );
    if (!encryptionKey) {
      throw new Error(
        "No suitable encryption key found in wallet_metadata.jwks"
      );
    }
    const publicKey = await jose.importJWK(encryptionKey);

    const alg =
      wallet_metadata.authorization_encryption_alg_values_supported?.[0] ||
      "ECDH-ES+A256KW";
    const enc =
      wallet_metadata.authorization_encryption_enc_values_supported?.[0] ||
      "A256GCM";

    const encryptedRequest = await new jose.CompactEncrypt(
      new TextEncoder().encode(signedJwt)
    )
      .setProtectedHeader({ alg: alg, enc: enc, typ: "oauth-authz-req+jwt" })
      .encrypt(publicKey);

    return encryptedRequest;
  }
  // console.log("signedJwt", signedJwt);
  return signedJwt;
}

export async function buildPaymentVpRequestJWT(
  client_id,
  redirect_uri,
  presentation_definition,
  privateKey = "",
  client_metadata = {},
  kid = null, // Default to an empty object,
  serverURL,
  response_type = "vp_token",

  merchant,
  currency,
  value,
  isRecurring,
  start_date,
  expiry_date,
  frequency,
  credential_ids
) {
  const nonce = generateNonce(16);
  const state = generateNonce(16);

  const transactionData = {
    type: "payment_data", // REQUIRED. The string that identifies the type of transaction data.
    credential_ids: [credential_ids], // REQUIRED. An array of strings, each referencing a Credential requested by the Verifier that can be used to authorize this transaction.
    transaction_data_hashes_alg: ["sha-256"], //OPTIONAL. An array of strings, each representing a hash algorithm identifier.
    payment_data: {
      payee: merchant,
      currency_amount: {
        currency: currency,
        value: value,
      },
    },
  };
  const base64EncodedTxData = Buffer.from(
    JSON.stringify(transactionData)
  ).toString("base64");

  // Construct the JWT payload
  let jwtPayload = {
    transaction_data: [base64EncodedTxData],
    response_type: response_type,
    response_mode: "direct_post",
    client_id: client_id, // this should match the dns record in the certificate (dss.aegean.gr)
    response_uri: redirect_uri,
    nonce: nonce,
    state: state,
    client_metadata: client_metadata, //
    // NOTE: Per OpenID4VP, wallets MUST ignore an iss claim in the authorization request.
    // To avoid confusion for implementers, we intentionally omit iss here.
    aud: "https://self-issued.me/v2",
    scope: "openid",
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 1, // Token expiration time (1 days)
  };

  if (isRecurring) {
    jwtPayload.payment_data.recurring_schedule = {
      // OPTIONAL. If present, it indicates a recurring payment with the following details:
      start_date: start_date,
      expiry_date: expiry_date,
      frequency: frequency,
    };
  }

  if (presentation_definition) {
    jwtPayload.presentation_definition = presentation_definition;
  }

  if (client_id.startsWith("x509_san_dns:")) {
    privateKey = fs.readFileSync("./x509/client_private_pkcs8.key", "utf8");
    const certificate = fs.readFileSync(
      "./x509/client_certificate.crt",
      "utf8"
    );
    // Convert certificate to Base64 without headers
    const certBase64 = certificate
      .replace("-----BEGIN CERTIFICATE-----", "")
      .replace("-----END CERTIFICATE-----", "")
      .replace(/\s+/g, "");

    const header = {
      alg: "RS256",
      typ: "oauth-authz-req+jwt",
      x5c: [certBase64],
    };

    const jwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, "RS256"));

    return { jwt, base64EncodedTxData, nonce, state };
  } else if (client_id.startsWith("did:")) {
    //TODO NOT COMPLETED SHOULD RETURN txDATA HASH
    const signingKey = {
      kty: "EC",
      x: "ijVgOGHvwHSeV1Z2iLF9pQLQAw7KcHF3VIjThhvVtBQ",
      y: "SfFShWAUGEnNx24V2b5G1jrhJNHmMwtgROBOi9OKJLc",
      crv: "P-256",
      use: "sig",
      kid: kid,
    };

    // Convert the private key to a KeyLike object
    const privateKeyObj = await jose.importPKCS8(
      privateKey,
      signingKey.alg || "ES256"
    );

    const jwtPayload = {
      response_type: response_type,
      response_mode: "direct_post",
      client_id: client_id, // DID the did of the verifier!!!!!!
      redirect_uri: redirect_uri,
      nonce: nonce,
      state: state,
      client_metadata: client_metadata,
    };
    if (presentation_definition) {
      jwtPayload.presentation_definition = presentation_definition;
    }
    if (response_type.indexOf("id_token") >= 0) {
      jwtPayload["id_token_type"] = "subject_signed";
      jwtPayload["scope"] = "openid";
    }

    // JWT header
    const header = {
      alg: signingKey.alg || "ES256",
      typ: "oauth-authz-req+jwt",
      kid: kid,
    };

    const jwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(privateKeyObj);

    return jwt;

    // Conditional signing based on client_id_scheme
  } else {
    throw new Error(
      "not supported client_id scheme for client_id:" + client_id
    );
  }
}

export async function jarOAutTokenResponse(
  generatedAccessToken,
  authorization_details,
  id_token = null
) {
  // these need to be singed by the same key/alg and keyId
  // exposed in the /jwks endpoint of the OAUTH server

  const privateKeyPem = fs.readFileSync("./private-key-pkcs8.pem", "utf-8");
  const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
  const signingKey = pemToJWK(publicKeyPem, "public");

  // Convert the private key to a KeyLike object
  const privateKeyObj = await jose.importPKCS8(
    privateKeyPem,
    signingKey.alg || "ES256"
  );

  const jwtPayload = {
    access_token: generatedAccessToken,
    refresh_token: generateRefreshToken(),
    token_type: "bearer",
    expires_in: 86400,
    // id_token: buildIdToken(serverURL, privateKey),
    c_nonce: generateNonce(),
    c_nonce_expires_in: 86400,
  };
  if (id_token) {
    jwtPayload.id_token = id_token;
  }
  if (authorization_details) {
    jwtPayload.authorization_details = authorizatiton_details;
  }

  // JWT header
  const header = {
    alg: signingKey.alg || "ES256",
    typ: "oauth-authz-req+jwt",
    kid: "aegean#authentication-key", //kid,
  };

  const jwt = await new jose.SignJWT(jwtPayload)
    .setProtectedHeader(header)
    .sign(privateKeyObj);

  return {
    access_token: jwt,
    token_type: "bearer",
    expires_in: jwtPayload.expires_in,
  };

  return jwt;
}

export async function decryptJWE(jweToken, privateKeyPEM, mode) {
  try {
    const privateKey = crypto.createPrivateKey(privateKeyPEM);

    // Decrypt the JWE using the private key
    const decryptedPayload = await jose.jwtDecrypt(jweToken, privateKey);

    if (mode === "direct_post.jwt") {
      // For direct_post.jwt, according to OpenID4VP spec, the JWE should decrypt to a JWT
      // console.log("Raw decryptedPayload for direct_post.jwt:", decryptedPayload);

      // First, try to get JWT from plaintext (per OpenID4VP spec)
      if (decryptedPayload.plaintext && decryptedPayload.plaintext.length > 0) {
        const decryptedJWT = new TextDecoder().decode(
          decryptedPayload.plaintext
        );
        // console.log("Found JWT in plaintext (per OpenID4VP spec):", decryptedJWT.substring(0, 100) + "...");
        return decryptedJWT; // Return JWT string for verification
      }

      // Fallback: check if vp_token is directly in payload (wallet-specific behavior)
      if (decryptedPayload.payload && decryptedPayload.payload.vp_token) {
        console.log(
          "Found vp_token in decrypted payload (wallet-specific behavior) DIVERGENT BEHAVIOR"
        );
        return decryptedPayload.payload;
      }

      throw new Error(
        "No JWT in plaintext or vp_token in payload for direct_post.jwt"
      );
    } else if (mode === "dc_api.jwt") {
      console.log("Decrypted JWE payload:", decryptedPayload.payload);
      // For HAIP dc_api.jwt, return the full decrypted payload
      // The calling code will handle extracting the VP token
      return decryptedPayload.payload;
    } else {
      // For other modes (legacy), parse and return disclosures
      // console.log(decryptedPayload);
      let presentation_submission =
        decryptedPayload.payload.presentation_submission;
      let disclosures = parseVP(decryptedPayload.payload.vp_token);
      // console.log(`diclosures in the VP found`);
      // console.log(disclosures);
      return disclosures;
    }
  } catch (error) {
    console.error("Error decrypting JWE:", error.message);
    throw error;
  }
}

export async function base64UrlEncodeSha256(codeVerifier) {
  // Convert the code verifier string to an ArrayBuffer with ASCII encoding
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);

  // Calculate the SHA-256 hash of the ArrayBuffer
  const hashBuffer = await crypto.subtle.digest("sha-256", data);

  // Convert the ArrayBuffer to a Uint8Array
  const hashArray = new Uint8Array(hashBuffer);

  // Convert the bytes to a Base64 string
  const base64String = btoa(String.fromCharCode.apply(null, hashArray));

  // Convert Base64 to Base64URL by replacing '+' with '-', '/' with '_', and stripping '='
  const base64UrlString = base64String
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  return base64UrlString;
}

function parseVP(vp_token) {
  // Check if vp_token is a string
  if (typeof vp_token !== "string") {
    throw new Error(
      `parseVP expects a string, but received: ${typeof vp_token}`
    );
  }

  let vpPartsArray = vp_token.split(".");
  let disclosuresPart = vpPartsArray[2]; //this is the actual sd-jdt from the vpToken

  let disclosuresArray = disclosuresPart.split("~").slice(1, -1); //get all elements apart form the first and last one
  // console.log(disclosuresArray);
  let decodedDisclosuresArray = disclosuresArray.map((element) => {
    return base64urlDecode(element);
  });
  return decodedDisclosuresArray;
}

const base64urlDecode = (input) => {
  // Convert base64url to base64 by adding padding characters
  const base64 = input
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(input.length + ((4 - (input.length % 4)) % 4), "=");
  // Decode base64
  const utf8String = atob(base64);
  // Convert UTF-8 string to byte array
  const bytes = new Uint8Array(utf8String.length);
  for (let i = 0; i < utf8String.length; i++) {
    bytes[i] = utf8String.charCodeAt(i);
  }
  let decodedString = new TextDecoder().decode(bytes);
  return JSON.parse(decodedString);
};

export async function didKeyToJwks(did) {
  if (did.startsWith("did:key:")) {
    const keyDidResolver = getResolver();
    const didResolver = new Resolver(keyDidResolver);

    const resolutionResult = await didResolver.resolve(did);
    const didDocument = resolutionResult.didDocument;
    if (!didDocument || !didDocument.verificationMethod) {
      console.error("Invalid DID Document for:", did);
      throw new Error("Invalid DID Document structure.");
    }
    const jwks = {
      keys: didDocument.verificationMethod.map((vm) => {
        const jwk = vm.publicKeyJwk;
        jwk.kid = vm.id;
        return jwk;
      }),
    };
    return jwks;
  } else if (did.startsWith("did:web:")) {
    // Handling did:web
    try {
      const [didPart] = did.split("#"); // we don't need the fragment for fetching did.json

      let didUrlPart = didPart.substring("did:web:".length);
      didUrlPart = decodeURIComponent(didUrlPart);

      const didParts = didUrlPart.split(":");
      const domain = didParts.shift();
      const path = didParts.join("/");

      let didDocUrl;
      if (path) {
        didDocUrl = `https://${domain}/${path}/did.json`;
      } else {
        didDocUrl = `https://${domain}/.well-known/did.json`;
      }

      const response = await fetch(didDocUrl);
      if (!response.ok) {
        throw new Error(`Failed to fetch DID document: ${response.statusText}`);
      }
      const didDocument = await response.json();

      if (!didDocument || !didDocument.verificationMethod) {
        // Handle cases where the document is empty or doesn't have verification methods
        console.error("Invalid DID Document for:", did);
        throw new Error("Invalid DID Document structure.");
      }

      const jwks = {
        keys: didDocument.verificationMethod.map((vm) => {
          const jwk = vm.publicKeyJwk;
          jwk.kid = vm.id;
          return jwk;
        }),
      };
      return jwks;
    } catch (e) {
      console.error("Error resolving did:web", e);
      throw e;
    }
  } else if (did.startsWith("did:jwk:")) {
    try {
      const jwkPart = did.substring("did:jwk:".length);
      const jwk = JSON.parse(Buffer.from(jwkPart, "base64url").toString());
      return { keys: [jwk] };
    } catch (e) {
      console.error("Error parsing did:jwk", e);
      throw e;
    }
  }
  return null;
}
export async function fetchWalletMetadata(metadataUrl) {
  if (!metadataUrl) {
    console.log("No wallet metadata URL provided, skipping fetch.");
    return null;
  }
  try {
    const response = await fetch(metadataUrl);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch wallet metadata: ${response.statusText}`
      );
    }
    const metadata = await response.json();
    console.log("Fetched wallet metadata:", metadata);
    return metadata;
  } catch (error) {
    console.error("Error fetching wallet metadata:", error);
    throw error;
  }
}
