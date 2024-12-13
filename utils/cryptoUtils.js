import crypto from "crypto";
import jwt from "jsonwebtoken";
import * as jose from "jose";
import base64url from "base64url";
import { error } from "console";
import fs from "fs";
import { generateRefreshToken } from "./tokenUtils.js";
import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";

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
        jwt_vp: {
          alg: ["EdDSA", "ES256K"],
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

export async function buildVpRequestJWT(
  client_id,
  redirect_uri,
  presentation_definition,
  privateKey = "",
  client_id_scheme = "redirect_uri", // Default to "redirect_uri"
  client_metadata = {},
  kid = null, // Default to an empty object,
  serverURL,
  response_type = "vp_token"
) {
  const nonce = generateNonce(16);
  const state = generateNonce(16);

  if (client_id_scheme === "x509_san_dns") {
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

    // The result is a JWS-signed JWT [RFC7519]. If signed, the Authorization Request Object SHOULD contain
    // the Claims iss (issuer) and aud (audience) as members with their semantics being the same as defined in the JWT [RFC7519] specification.
    // The value of aud should be the value of the authorization server (AS) issuer, as defined in RFC 8414 [RFC8414]

    // Construct the JWT payload
    let jwtPayload = {
      response_type: response_type,
      response_mode: "direct_post",
      client_id: client_id, // this should match the dns record in the certificate (dss.aegean.gr)
      client_id_scheme: client_id_scheme,
      response_uri: redirect_uri,
      nonce: nonce,
      state: state,
      client_metadata: client_metadata, //
      iss: serverURL,
      aud: serverURL,
    };
    // SIOPv2 supports only redirect_uri and did so x509 cannot be used

    // if (response_type.indexOf("id_token") >=0 ) {
    //   jwtPayload["id_token_type"] = "subject_signed";
    //   jwtPayload["scope"] = "openid";
    // }

    if (presentation_definition) {
      jwtPayload.presentation_definition = presentation_definition;
    }

    // Define the JWT header
    // const header = {
    //   alg: "ES256",
    //   kid: `aegean#authentication-key`, // Ensure this kid is resolvable from the did.json endpoint
    // };
    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [certBase64],
    };

    const jwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, "RS256"));

    return jwt;
  } else if (client_id_scheme.indexOf("did") >= 0) {
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
      client_id_scheme: client_id_scheme,
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

    // Conditional signing based on client_id_scheme
  } else {
    throw new Error("not supported client_id_scheme:" + client_id_scheme);
  }
}

export async function buildPaymentVpRequestJWT(
  client_id,
  redirect_uri,
  presentation_definition,
  privateKey = "",
  client_id_scheme = "redirect_uri", // Default to "redirect_uri"
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
  frequency
) {
  const nonce = generateNonce(16);
  const state = generateNonce(16);

  if (client_id_scheme === "x509_san_dns") {
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

    // Construct the JWT payload
    let jwtPayload = {
      type: "payment_data", // REQUIRED. The string that identifies the type of transaction data.
      credential_ids: ["PaymentWalletAttestationAccount"], // REQUIRED. An array of strings, each referencing a Credential requested by the Verifier that can be used to authorize this transaction.
      transaction_data_hashes_alg: ["sha-256"], //OPTIONAL. An array of strings, each representing a hash algorithm identifier.
      payment_data: {
        // REQUIRED. An object related to payment transactions
        payee: merchant,
        currency_amount: {
          currency: currency,
          value: value,
        },
      },
      response_type: response_type,
      response_mode: "direct_post",
      client_id: client_id, // this should match the dns record in the certificate (dss.aegean.gr)
      client_id_scheme: client_id_scheme,
      response_uri: redirect_uri,
      nonce: nonce,
      state: state,
      client_metadata: client_metadata, //
      iss: serverURL,
      aud: serverURL,
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

    // Define the JWT header
    // const header = {
    //   alg: "ES256",
    //   kid: `aegean#authentication-key`, // Ensure this kid is resolvable from the did.json endpoint
    // };
    const header = {
      alg: "RS256",
      typ: "JWT",
      x5c: [certBase64],
    };

    const jwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, "RS256"));

    return jwt;
  } else if (client_id_scheme.indexOf("did") >= 0) {
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
      client_id_scheme: client_id_scheme,
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

    // Conditional signing based on client_id_scheme
  } else {
    throw new Error("not supported client_id_scheme:" + client_id_scheme);
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
    typ: "JWT",
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
    const privateKey = crypto.createPrivateKey(privateKeyPEM);

    // Decrypt the JWE using the private key
    const decryptedPayload = await jose.jwtDecrypt(jweToken, privateKey);
    // console.log(decryptedPayload);
    let presentation_submission =
      decryptedPayload.payload.presentation_submission;
    let disclosures = parseVP(decryptedPayload.payload.vp_token);
    console.log(`diclosures in the VP found`);
    console.log(disclosures);
    return disclosures;
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
  // getResolver will return an object with a key/value pair of { "key": resolver } where resolver is a function used by the generic DID resolver.
  const keyResolver = getResolver();
  const didResolver = new Resolver(keyResolver);
  const doc = await didResolver.resolve(did);
  console.log(doc.didDocument.verificationMethod.publicKeyJwk)

  return doc.didDocument.verificationMethod[0].publicKeyJwk
}
