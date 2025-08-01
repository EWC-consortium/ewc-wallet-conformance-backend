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

// Helper function to filter client metadata based on response mode
export function filterClientMetadataForResponseMode(clientMetadata, responseMode) {
  // Only include encryption parameters for JWT response modes
  const jwtResponseModes = ["direct_post.jwt", "dc_api.jwt"];
  
  if (jwtResponseModes.includes(responseMode)) {
    // Include all encryption parameters for JWT response modes
    return clientMetadata;
  } else {
    // Remove encryption parameters for non-JWT response modes
    const filteredMetadata = { ...clientMetadata };
    
    // Remove jwks if present
    if (filteredMetadata.jwks) {
      delete filteredMetadata.jwks;
    }
    
    // Remove encrypted_response_enc_values_supported if present
    if (filteredMetadata.encrypted_response_enc_values_supported) {
      delete filteredMetadata.encrypted_response_enc_values_supported;
    }
    
    return filteredMetadata;
  }
}

export async function buildVpRequestJWT(
  client_id,
  redirect_uri,
  privateKey = "",
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
  verifier_attestations = null
) {
  if(!nonce) nonce = generateNonce(16);
  const state = generateNonce(16);

  // Validate response_mode
  const allowedResponseModes = ["direct_post", "direct_post.jwt", "dc_api.jwt"];
  if (!allowedResponseModes.includes(response_mode)) {
    console.log("response_mode", response_mode);
    throw new Error(`Invalid response_mode. Must be one of: ${allowedResponseModes.join(", ")}`);
  }

  // Construct the JWT payload
  let jwtPayload = {
    response_type: response_type,
    response_mode: response_mode,
    client_id: client_id,
    response_uri: redirect_uri,
    nonce: nonce,
    state: state,
    client_metadata: client_metadata,
    aud: audience, // Use the audience parameter
  };
  // console.log("wallet_nonce", wallet_nonce);
  if(wallet_nonce) jwtPayload.wallet_nonce = wallet_nonce;

  // Add dcql_query if provided
  if (dcql_query) {
    jwtPayload.dcql_query = dcql_query;
  }

  // Add transaction_data if provided
  if (transaction_data) {
    jwtPayload.transaction_data = transaction_data;
  }

  if (verifier_attestations) {
    jwtPayload.verifier_attestations = verifier_attestations;
  }

  let signedJwt;

  // Determine signing algorithm based on wallet metadata
  let signingAlg = 'ES256'; // Default algorithm
  if (client_id.startsWith("x509_san_dns:")) {
    signingAlg = 'RS256';
  }

  const verifierSupportedAlgs = ['ES256', 'ES384', 'RS256'];

  if (wallet_metadata && wallet_metadata.request_object_signing_alg_values_supported) {
    const walletSupportedAlgs = wallet_metadata.request_object_signing_alg_values_supported;
    const commonAlg = walletSupportedAlgs.find(alg => verifierSupportedAlgs.includes(alg));

    if (commonAlg) {
      signingAlg = commonAlg;
    } else {
      console.warn("No common signing algorithm found. Defaulting to", signingAlg);
    }
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
      alg: signingAlg,
      typ: "oauth-authz-req+jwt",
      x5c: [certBase64],
    };

    signedJwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, signingAlg));
  } else if (client_id.startsWith("decentralized_identifier:")) {
    const did_part = client_id.substring("decentralized_identifier:".length);
    if (did_part.startsWith('did:jwk:')) {
      const header = {
        alg: signingAlg,
        typ: "oauth-authz-req+jwt",
        kid: kid 
      };

      signedJwt = await new jose.SignJWT(jwtPayload)
        .setProtectedHeader(header)
        .sign(await jose.importPKCS8(privateKey, signingAlg));
    } else if (did_part.startsWith("did:web:")) {
      // Handle did:web case
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
        signingAlg
      );

      // JWT header
      const header = {
        alg: signingAlg,
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
    throw new Error("not supported client_id prefix for client_id:" + client_id);
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
      throw new Error("No suitable encryption key found in wallet_metadata.jwks");
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

  // Determine signing algorithm based on wallet metadata
  let signingAlg = 'ES256'; // Default algorithm
  if (client_id.startsWith("x509_san_dns:")) {
    signingAlg = 'RS256';
  }

  const verifierSupportedAlgs = ['ES256', 'ES384', 'RS256'];

  if (wallet_metadata && wallet_metadata.request_object_signing_alg_values_supported) {
    const walletSupportedAlgs = wallet_metadata.request_object_signing_alg_values_supported;
    const commonAlg = walletSupportedAlgs.find(alg => verifierSupportedAlgs.includes(alg));

    if (commonAlg) {
      signingAlg = commonAlg;
    } else {
      console.warn("No common signing algorithm found. Defaulting to", signingAlg);
    }
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
      alg: signingAlg,
      typ: "JWT",
      x5c: [certBase64],
    };

    const jwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, signingAlg));

    return { jwt, base64EncodedTxData };
  } else if (client_id.startsWith("decentralized_identifier:")) {
    const did_part = client_id.substring("decentralized_identifier:".length);
    if (did_part.startsWith('did:jwk:')) {
      const header = {
        alg: signingAlg,
        typ: "oauth-authz-req+jwt",
        kid: kid 
      };

      const jwt = await new jose.SignJWT(jwtPayload)
        .setProtectedHeader(header)
        .sign(await jose.importPKCS8(privateKey, signingAlg));

      return jwt;
    } else if (did_part.startsWith("did:web:")) {
      // Handle did:web case
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
        typ: "JWT",
        kid: kid,
      };

      const jwt = await new jose.SignJWT(jwtPayload)
        .setProtectedHeader(header)
        .sign(privateKeyObj);

      return jwt;
    } else {
      throw new Error("Unsupported DID method: " + client_id);
    }
  } else {
    throw new Error("not supported client_id prefix for client_id:" + client_id);
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

export async function decryptJWE(jweToken, privateKeyPEM) {
  try {
    console.log("Attempting to decrypt JWE token...");
    console.log("JWE token format check:", typeof jweToken, jweToken ? jweToken.substring(0, 50) + "..." : "null");
    
    const privateKey = await jose.importPKCS8(privateKeyPEM, "ES256");
    console.log("Private key imported successfully");

    // Decrypt the JWE using the private key
    // For ECDH-ES+A256KW, we need to let jose auto-detect the algorithm from the JWE header
    const { plaintext, protectedHeader } = await jose.compactDecrypt(jweToken, privateKey);
    // console.log("JWE decrypted successfully, protected header:", protectedHeader);
    
    const decryptedPayload = JSON.parse(new TextDecoder().decode(plaintext));
    console.log("Decrypted payload parsed successfully");
    
    return decryptedPayload;
  } catch (error) {
    console.error("Error decrypting JWE:", error);
    console.error("Error details:", {
      name: error.name,
      message: error.message,
      code: error.code,
      stack: error.stack
    });
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
      throw new Error(`Failed to fetch wallet metadata: ${response.statusText}`);
    }
    const metadata = await response.json();
    console.log("Fetched wallet metadata:", metadata);
    return metadata;
  } catch (error) {
    console.error("Error fetching wallet metadata:", error);
    throw error;
  }
}

