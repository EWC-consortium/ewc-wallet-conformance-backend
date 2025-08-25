import jwt from "jsonwebtoken";
import {
  createSignerVerifier,
  digest,
  generateSalt,
  createSignerVerifierX509,
  pemToBase64Der,
} from "../utils/sdjwtUtils.js";
import { pemToJWK, generateNonce, didKeyToJwks } from "../utils/cryptoUtils.js";
import fs from "fs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";

import {
  getPIDSDJWTData,
  getStudentIDSDJWTData,
  getGenericSDJWTData,
  getEPassportSDJWTData,
  getVReceiptSDJWTData,
  getVReceiptSDJWTDataWithPayload,
  createPaymentWalletAttestationPayload,
  createPhotoIDAttestationPayload,
  getFerryBoardingPassSDJWTData,
  createPCDAttestationPayload,
  getLoyaltyCardSDJWTDataWithPayload,
} from "../utils/credPayloadUtil.js";

import {
  MDoc,
  Document
} from "@auth0/mdl";

import cryptoModule from "crypto";
import { Buffer } from "buffer";
import { encode } from "cbor-x";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
const privateKeyPemX509 = fs.readFileSync(
  "./x509EC/ec_private_pkcs8.key",
  "utf8"
);
const certificatePemX509 = fs.readFileSync(
  "./x509EC/client_certificate.crt",
  "utf8"
);

// Load issuer configuration for KID and JWK header preference
let issuerConfigValues = {};
try {
  const issuerConfigRaw = fs.readFileSync("./data/issuer-config.json", "utf-8");
  issuerConfigValues = JSON.parse(issuerConfigRaw);
} catch (err) {
  console.warn("Could not load ./data/issuer-config.json for KID, using defaults.", err);
}
const defaultSigningKid = issuerConfigValues.default_signing_kid || "aegean#authentication-key";




// Maps claims from existing payload to mDL format
// This is a simplified mapper and needs to be extended for different VCTs
function mapClaimsToMdl(claims, vct) {
  const mdlClaims = {};
  // Standard mDL claims (ISO 18013-5) often go into 'org.iso.18013.5.1' namespace
  // Mapping common claims:
  if (claims.family_name) mdlClaims.family_name = claims.family_name;
  if (claims.given_name) mdlClaims.given_name = claims.given_name;
  
  // mDL uses 'birth_date', SD-JWT might use 'birthdate'
  if (claims.birthdate) mdlClaims.birth_date = claims.birthdate; 
  else if (claims.birth_date) mdlClaims.birth_date = claims.birth_date;

  // mDL 'issue_date' and 'expiry_date' for the document itself
  if (claims.issuance_date) mdlClaims.issue_date = claims.issuance_date; // Map PID's issuance_date
  else if (claims.issue_date) mdlClaims.issue_date = claims.issue_date;

  if (claims.expiry_date) mdlClaims.expiry_date = claims.expiry_date; // Map PID's expiry_date

  // Placeholder for other claims and VCT specific mappings
  // For example, for a driver's license (mDL docType):
  // if (vct === 'some_driver_license_vct') {
  //   mdlClaims.driving_privileges = claims.driving_privileges;
  //   mdlClaims.portrait = claims.portrait; // Needs to be bytes
  //   mdlClaims.document_number = claims.document_number;
  //   mdlClaims.issuing_country = claims.issuing_country;
  // }

  if (claims.unique_id && (vct === "VerifiablePIDSDJWT" || vct === "urn:eu.europa.ec.eudi:pid:1")){
      mdlClaims.unique_identifier = claims.unique_id; // Example mapping for PID
  }

  // Add more specific mappings based on vct and mDL data element definitions
  // console.log("Mapped mDL claims:", mdlClaims);
  return mdlClaims;
}

const DOC_TYPE_MDL = "org.iso.18013.5.1.mDL";
const DEFAULT_MDL_NAMESPACE = "org.iso.18013.5.1";

export async function handleVcSdJwtFormat(
  requestBody,
  sessionObject,
  serverURL,
  format="vc+sd-jwt"
) {
  const vct = requestBody.vct;

  let signer, verifier;
  let headerOptions; // Define headerOptions here to be populated based on sig type

  // Helpers to compute issuer DID and KID based on selected signature type
  const computeDidWebFromServer = () => {
    const proxyPath = process.env.PROXY_PATH || null;
    let controller = serverURL;
    if (proxyPath) {
      controller = serverURL.replace("/" + proxyPath, "") + ":" + proxyPath;
    }
    controller = controller.replace("https://", "").replace("http://", "");
    const did = `did:web:${controller}`;
    const kid = `${did}#keys-1`;
    return { did, kid };
  };

  const computeDidJwkFromPublic = () => {
    const publicJwkForSigning = pemToJWK(publicKeyPem, "public");
    const did = `did:jwk:${Buffer.from(JSON.stringify(publicJwkForSigning)).toString("base64url")}`;
    const kid = `${did}#0`;
    return { did, kid };
  };

  const effectiveSignatureType = sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509"
    ? "x509"
    : sessionObject.signatureType;

  if (effectiveSignatureType === "x509") {
    console.log("x509 signature type selected.");
    ({ signer, verifier } = await createSignerVerifierX509(
      privateKeyPemX509,
      certificatePemX509
    ));
    headerOptions = {
      header: {
        x5c: [pemToBase64Der(certificatePemX509)],
        typ: format
      },
    };
  } else { // Covers did:web and did:jwk (and legacy jwk/kid-jwk)
    const publicJwkForSigning = pemToJWK(publicKeyPem, "public");
    ({ signer, verifier } = await createSignerVerifier(
      pemToJWK(privateKey, "private"),
      publicJwkForSigning
    ));

    let joseHeader = {};
    if (effectiveSignatureType === "did:web") {
      console.log("did:web signature type selected.");
      const { kid } = computeDidWebFromServer();
      joseHeader = {
        kid: kid,
        alg: "ES256",
        typ: format
      };
    } else {
      // Default to did:jwk for DIIP compliance when not using did:web/x509
      console.log("did:jwk signature type selected (or legacy jwk/kid-jwk coerced to did:jwk).");
      const { kid } = computeDidJwkFromPublic();
      joseHeader = {
        kid: kid,
        alg: "ES256",
        typ: format
      };
    }
    headerOptions = { header: joseHeader };
  }

  // console.log("dc+sd-jwt ", vct);

  // Normalize key proof input according to ID2 (supports 'proof' or 'proofs')
  if (requestBody.proof && requestBody.proofs) {
    const error = new Error("'proof' and 'proofs' MUST NOT both be present");
    error.status = 400;
    throw error;
  }
  let normalizedProofJwt;
  if (requestBody.proof && requestBody.proof.jwt) {
    normalizedProofJwt = requestBody.proof.jwt;
  } else if (requestBody.proofs) {
    const proofTypeKeys = Object.keys(requestBody.proofs);
    if (proofTypeKeys.length !== 1 || proofTypeKeys[0] !== "jwt") {
      const error = new Error("Unsupported or invalid 'proofs' structure: only 'jwt' is supported and exactly one proof type key is allowed");
      error.status = 400;
      throw error;
    }
    const jwtProofs = requestBody.proofs.jwt;
    if (!Array.isArray(jwtProofs) || jwtProofs.length === 0) {
      const error = new Error("'proofs.jwt' MUST be a non-empty array");
      error.status = 400;
      throw error;
    }
    const requestedCredentialIdentifier = requestBody.credential_identifier;
    const selectedProof = requestedCredentialIdentifier
      ? jwtProofs.find((p) => p && p.credential_identifier === requestedCredentialIdentifier)
      : jwtProofs[0];
    if (!selectedProof || !selectedProof.jwt) {
      const error = new Error("No usable JWT proof found in 'proofs'");
      error.status = 400;
      throw error;
    }
    normalizedProofJwt = selectedProof.jwt;
    // Normalize structure for downstream code that reads requestBody.proof.jwt
    requestBody.proof = { proof_type: "jwt", jwt: normalizedProofJwt };
  }
  if (!normalizedProofJwt) {
    const error = new Error("proof not found");
    error.status = 400;
    throw error;
  }

  const decodedWithHeader = jwt.decode(normalizedProofJwt, {
    complete: true,
  });
  const holderJWKS = decodedWithHeader.header;

  const credType = vct;
  let credPayload = {};

  let issuerName = serverURL;
  const match = serverURL.match(/^(?:https?:\/\/)?([^/]+)/);
  if (match) {
    issuerName = match[1];
  }
  //TODO fix this
  issuerName = "https://dss.aegean.gr";

  // Determine credential payload based on type
  switch (credType) {
    case "VerifiableIdCardJwtVc":
    case "VerifiablePIDSDJWT":
    case "urn:eu.europa.ec.eudi:pid:1":
      credPayload = getPIDSDJWTData();
      break;
    case "VerifiableePassportCredentialSDJWT":
      credPayload = getEPassportSDJWTData();
      break;
    case "VerifiableStudentIDSDJWT":
      credPayload = sessionObject
        ? getStudentIDSDJWTData(sessionObject.credentialPayload, null)
        : getVReceiptSDgetStudentIDSDJWTDataJWTData();
      break;
    case "ferryBoardingPassCredential":
    case "VerifiableFerryBoardingPassCredentialSDJWT":
      credPayload = await getFerryBoardingPassSDJWTData();
      break;
    case "VerifiablePortableDocumentA1SDJWT":
      credPayload = getGenericSDJWTData();
      break;
    case "PaymentWalletAttestation":
      credPayload = createPaymentWalletAttestationPayload(issuerName);
      break;
    case "VerifiablevReceiptSDJWT":
      credPayload = sessionObject
        ? getVReceiptSDJWTDataWithPayload(sessionObject.credentialPayload)
        : getVReceiptSDJWTData();
      break;
    case "VerifiablePortableDocumentA2SDJWT":
      credPayload = getGenericSDJWTData();
      break;
    case "eu.europa.ec.eudi.photoid.1":
      credPayload = createPhotoIDAttestationPayload(issuerName);
      break;
    case "eu.europa.ec.eudi.pcd.1":
    case "urn:eu.europa.ec.eudi:pid:1:mso_mdoc":
      credPayload = createPCDAttestationPayload(issuerName);
      break;
    case "LoyaltyCard":
      credPayload = getLoyaltyCardSDJWTDataWithPayload(
        sessionObject.credentialPayload
      );
      break;
    default:
      throw new Error(`Unsupported credential type: ${credType}`);
  }

  // Handle holder binding per DIIP: MUST include cnf.kid as DID URL from Holder's authentication VM
  let cnf;
  if (holderJWKS && holderJWKS.kid && holderJWKS.kid.startsWith("did:")) {
    cnf = { kid: holderJWKS.kid };
  } else if (holderJWKS && holderJWKS.jwk) {
    // Derive did:jwk from embedded JWK
    const holderDid = `did:jwk:${Buffer.from(JSON.stringify(holderJWKS.jwk)).toString("base64url")}#0`;
    cnf = { kid: holderDid };
  } else if (holderJWKS && holderJWKS.kid && holderJWKS.kid.startsWith("did:key:")) {
    // Non-required by DIIP, but attempt resolution and fallback to first JWK -> derive did:jwk kid
    try {
      const keys = await didKeyToJwks(holderJWKS.kid);
      if (keys && keys.keys && keys.keys[0]) {
        const holderDid = `did:jwk:${Buffer.from(JSON.stringify(keys.keys[0])).toString("base64url")}#0`;
        cnf = { kid: holderDid };
      }
    } catch (e) {
      // Fallback to embedding JWK if resolution fails (non-DIIP compliant)
      cnf = { jwk: (await didKeyToJwks(holderJWKS.kid)).keys[0] };
    }
  }
  if (!cnf) {
    // As a last resort, keep old behavior but this is not DIIP-compliant
    cnf = { jwk: holderJWKS?.jwk };
  }

  const now = new Date();
  const expiryDate = new Date(now);
  expiryDate.setMonth(now.getMonth() + 6);

  if (format === "jwt_vc_json" || format === "vc+sd-jwt") {
    console.log("Issuing a jwt_vc format credential");
    // Compute issuer DID and kid for header already done; compute issuer DID for payload as well
    let issuerDidForPayload;
    if (effectiveSignatureType === "x509") {
      // X.509 mode: keep existing issuer as server URL (out of DIIP scope)
      issuerDidForPayload = serverURL;
    } else if (effectiveSignatureType === "did:web") {
      issuerDidForPayload = computeDidWebFromServer().did;
    } else {
      issuerDidForPayload = computeDidJwkFromPublic().did;
    }
    const vcPayload = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", vct],
      credentialSubject: credPayload.claims,
      issuer: issuerDidForPayload,
      validFrom: now.toISOString(),
      validUntil: expiryDate.toISOString(),
    };

    const sdjwt = new SDJwtVcInstance({
      signer,
      verifier,
      signAlg: "ES256",
      hasher: digest,
      hashAlg: "sha-256",
      saltGenerator: generateSalt,
    });
    const sdPayload = {
      iss: issuerDidForPayload,
      iat: Math.floor(now.getTime() / 1000),
      nbf: Math.floor(now.getTime() / 1000),
      exp: Math.floor(expiryDate.getTime() / 1000),
      ...vcPayload,  
      cnf: cnf,
      ...(requestBody.status_reference
        ? { status: requestBody.status_reference }
        : {}),
    };

    const disclosureFrame = {
      credentialSubject: credPayload.disclosureFrame
    };

    headerOptions = {
      header: {
        ...headerOptions.header,   
        typ: 'vc+sd-jwt',
        cty: 'vc'
      }
    };
    const credential = await sdjwt.issue(sdPayload, disclosureFrame, headerOptions);
    return credential;
  
  } else if (format === "dc+sd-jwt") {
    console.log("Issuing a dc+sd-jwt format credential");
    // Compute issuer DID for payload
    let issuerDidForPayload;
    if (effectiveSignatureType === "x509") {
      issuerDidForPayload = serverURL;
    } else if (effectiveSignatureType === "did:web") {
      issuerDidForPayload = computeDidWebFromServer().did;
    } else {
      issuerDidForPayload = computeDidJwkFromPublic().did;
    }
    const sdjwt = new SDJwtVcInstance({
      signer,
      verifier,
      signAlg: "ES256",
      hasher: digest,
      hashAlg: "sha-256",
      saltGenerator: generateSalt,
    });
    // Issue credential
    const credential = await sdjwt.issue(
      {
        iss: issuerDidForPayload,
        iat: Math.floor(Date.now() / 1000),
        nbf: Math.floor(Date.now() / 1000),
        exp: Math.floor(expiryDate.getTime() / 1000),
        vct: credType,
        ...credPayload.claims,
        cnf,
        ...(requestBody.status_reference
          ? { status: requestBody.status_reference }
          : {}),
      },
      credPayload.disclosureFrame,
      headerOptions
    );
    console.log("Credential issued: ", credential);
    return credential;
  } else if (format === "mDL" || format === "mdl") {
    console.log("Attempting to generate mDL credential using @auth0/mdl...");
    try {
      const mDLClaimsMapped = mapClaimsToMdl(credPayload.claims, vct);
      const devicePublicKeyJwk = cnf.jwk;

      // Determine signature type for mDL
      const currentEffectiveSignatureType =
        (sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509") || sessionObject.signatureType === "x509"
        ? "x509"
        : "jwk";

      // Prepare signing arguments based on signature type
      let issuerPrivateKeyForSign, issuerCertificateForSign;

      if (currentEffectiveSignatureType === "x509") {
        console.log("Using X.509 for mDL signing with @auth0/mdl.");
        // Convert PEM to JWK for @auth0/mdl
        issuerPrivateKeyForSign = pemToJWK(privateKeyPemX509, "private");
        issuerCertificateForSign = certificatePemX509; // Certificate stays as PEM
      } else { // "jwk"
        console.log("Using JWK for mDL signing with @auth0/mdl.");
        // Convert PEM to JWK for @auth0/mdl
        issuerPrivateKeyForSign = pemToJWK(privateKey, "private");
        issuerCertificateForSign = certificatePemX509; // Certificate stays as PEM
      }

      // Create and sign document using @auth0/mdl API
      const document = await new Document(DOC_TYPE_MDL)
        .addIssuerNameSpace(DEFAULT_MDL_NAMESPACE, mDLClaimsMapped)
        .useDigestAlgorithm('SHA-256')
        .addValidityInfo({
          signed: new Date(),
          validFrom: new Date(), // Add validFrom as shown in documentation
          validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year validity
        })
        .addDeviceKeyInfo({ deviceKey: devicePublicKeyJwk })
        .sign({
          issuerPrivateKey: issuerPrivateKeyForSign,
          issuerCertificate: issuerCertificateForSign,
          alg: 'ES256',
        });

      const issuerSigned = document.issuerSigned;
      const cborIssuerSigned = encode(issuerSigned);


      // Debug: Examine the raw CBOR bytes
      console.log("=== CBOR Debug Information ===");
      console.log(`CBOR byte length: ${cborIssuerSigned.length}`);
      console.log(`First 20 bytes (hex): ${Buffer.from(cborIssuerSigned.slice(0, 20)).toString('hex')}`);
      console.log(`First 20 bytes (decimal): [${Array.from(cborIssuerSigned.slice(0, 20)).join(', ')}]`);
      
      // Check if it's valid CBOR by trying to parse it
      try {
        // Let's see what the raw mdoc structure looks like
        console.log("Raw mdoc type:", typeof cborIssuerSigned);
        console.log("Raw mdoc constructor:", cborIssuerSigned.constructor.name);
        console.log("Is Buffer?", Buffer.isBuffer(cborIssuerSigned));
        console.log("Is Uint8Array?", cborIssuerSigned instanceof Uint8Array);
      } catch (e) {
        console.error("Error examining mdoc structure:", e);
      }

      let encodedMobileDocument = Buffer.from(cborIssuerSigned).toString(
        "base64url"
      );
      console.log(
        "mDL Credential generated with @auth0/mdl (base64url):",
        encodedMobileDocument.substring(0, 100) + "..."
      );

      console.log("=== End CBOR Debug ===");

      return encodedMobileDocument;
    } catch (error) {
      console.error("Error generating mDL credential with @auth0/mdl:", error);
      throw new Error(
        `Failed to generate mDL with @auth0/mdl: ${error.message}`
      );
    }
  } else {
    throw new Error(`Unsupported format: ${format}`);
  }
}

export async function handleVcSdJwtFormatDeferred(sessionObject, serverURL) {
  const requestBody = sessionObject.requestBody;
  const vct = requestBody.vct;
  let { signer, verifier } = await createSignerVerifierX509(
    privateKeyPemX509,
    certificatePemX509
  );
  console.log("vc+sd-jwt ", vct);

  // Normalize key proof input according to ID2 (supports 'proof' or 'proofs')
  if (requestBody.proof && requestBody.proofs) {
    const error = new Error("'proof' and 'proofs' MUST NOT both be present");
    error.status = 400;
    throw error;
  }
  let normalizedProofJwt;
  if (requestBody.proof && requestBody.proof.jwt) {
    normalizedProofJwt = requestBody.proof.jwt;
  } else if (requestBody.proofs) {
    const proofTypeKeys = Object.keys(requestBody.proofs);
    if (proofTypeKeys.length !== 1 || proofTypeKeys[0] !== "jwt") {
      const error = new Error("Unsupported or invalid 'proofs' structure: only 'jwt' is supported and exactly one proof type key is allowed");
      error.status = 400;
      throw error;
    }
    const jwtProofs = requestBody.proofs.jwt;
    if (!Array.isArray(jwtProofs) || jwtProofs.length === 0) {
      const error = new Error("'proofs.jwt' MUST be a non-empty array");
      error.status = 400;
      throw error;
    }
    const requestedCredentialIdentifier = requestBody.credential_identifier;
    const selectedProof = requestedCredentialIdentifier
      ? jwtProofs.find((p) => p && p.credential_identifier === requestedCredentialIdentifier)
      : jwtProofs[0];
    if (!selectedProof || !selectedProof.jwt) {
      const error = new Error("No usable JWT proof found in 'proofs'");
      error.status = 400;
      throw error;
    }
    normalizedProofJwt = selectedProof.jwt;
    // Normalize structure for downstream code that reads requestBody.proof.jwt
    requestBody.proof = { proof_type: "jwt", jwt: normalizedProofJwt };
  }
  if (!normalizedProofJwt) {
    const error = new Error("proof not found");
    error.status = 400;
    throw error;
  }

  const decodedWithHeader = jwt.decode(normalizedProofJwt, {
    complete: true,
  });
  const holderJWKS = decodedWithHeader.header;

  const isHaip = sessionObject ? sessionObject.isHaip : false;
  if (!isHaip) {
    ({ signer, verifier } = await createSignerVerifier(
      pemToJWK(privateKey, "private"),
      pemToJWK(publicKeyPem, "public")
    ));
  }

  const sdjwt = new SDJwtVcInstance({
    signer,
    verifier,
    signAlg: "ES256",
    hasher: digest,
    hashAlg: "sha-256",
    saltGenerator: generateSalt,
  });

  const credType = vct;
  let credPayload = {};

  let issuerName = serverURL;
  const match = serverURL.match(/^(?:https?:\/\/)?([^/]+)/);
  if (match) {
    issuerName = match[1];
  }
  //TODO fix this
  issuerName = "https://dss.aegean.gr";

  // Determine credential payload based on type
  switch (credType) {
    case "VerifiableIdCardJwtVc":
    case "VerifiablePIDSDJWT":
    case "urn:eu.europa.ec.eudi:pid:1":
      credPayload = getPIDSDJWTData();
      break;
    case "VerifiableePassportCredentialSDJWT":
      credPayload = getEPassportSDJWTData();
      break;
    case "VerifiableStudentIDSDJWT":
      credPayload = getStudentIDSDJWTData();
      break;
    case "ferryBoardingPassCredential":
    case "VerifiableFerryBoardingPassCredentialSDJWT":
      credPayload = await getFerryBoardingPassSDJWTData();
      break;
    case "VerifiablePortableDocumentA1SDJWT":
      credPayload = getGenericSDJWTData();
      break;
    case "PaymentWalletAttestation":
      credPayload = createPaymentWalletAttestationPayload(issuerName);
      break;
    case "VerifiablevReceiptSDJWT":
      credPayload = sessionObject
        ? getVReceiptSDJWTDataWithPayload(sessionObject.credentialPayload)
        : getVReceiptSDJWTData();
      break;
    case "VerifiablePortableDocumentA2SDJWT":
      credPayload = getGenericSDJWTData();
      break;
    case "eu.europa.ec.eudi.photoid.1":
      credPayload = createPhotoIDAttestationPayload(issuerName);
      break;
    case "eu.europa.ec.eudi.pcd.1":
      credPayload = createPCDAttestationPayload(issuerName);
      break;
    default:
      throw new Error(`Unsupported credential type: ${credType}`);
  }

  // Handle holder binding (DIIP): prefer DID URL in cnf.kid
  let cnf;
  if (holderJWKS && holderJWKS.kid && holderJWKS.kid.startsWith("did:")) {
    cnf = { kid: holderJWKS.kid };
  } else if (holderJWKS && holderJWKS.jwk) {
    const holderDid = `did:jwk:${Buffer.from(JSON.stringify(holderJWKS.jwk)).toString("base64url")}#0`;
    cnf = { kid: holderDid };
  } else if (holderJWKS && holderJWKS.kid && holderJWKS.kid.startsWith("did:key:")) {
    try {
      const keys = await didKeyToJwks(holderJWKS.kid);
      if (keys && keys.keys && keys.keys[0]) {
        const holderDid = `did:jwk:${Buffer.from(JSON.stringify(keys.keys[0])).toString("base64url")}#0`;
        cnf = { kid: holderDid };
      }
    } catch (e) {
      cnf = { jwk: (await didKeyToJwks(holderJWKS.kid)).keys[0] };
    }
  }
  if (!cnf) {
    cnf = { jwk: holderJWKS?.jwk };
  }

  // Prepare issuance headers per DIIP
  const computeDidWebFromServer = () => {
    const proxyPath = process.env.PROXY_PATH || null;
    let controller = serverURL;
    if (proxyPath) {
      controller = serverURL.replace("/" + proxyPath, "") + ":" + proxyPath;
    }
    controller = controller.replace("https://", "").replace("http://", "");
    const did = `did:web:${controller}`;
    const kid = `${did}#keys-1`;
    return { did, kid };
  };
  const computeDidJwkFromPublic = () => {
    const publicJwkForSigning = pemToJWK(publicKeyPem, "public");
    const did = `did:jwk:${Buffer.from(JSON.stringify(publicJwkForSigning)).toString("base64url")}`;
    const kid = `${did}#0`;
    return { did, kid };
  };
  let headerOptions;
  if (isHaip || process.env.ISSUER_SIGNATURE_TYPE === "x509") {
    headerOptions = {
      header: {
        x5c: [pemToBase64Der(certificatePemX509)],
        typ: "vc+sd-jwt",
      },
    };
  } else if (sessionObject.signatureType === "did:web") {
    const { kid } = computeDidWebFromServer();
    headerOptions = { header: { kid, alg: "ES256", typ: "vc+sd-jwt" } };
  } else {
    const { kid } = computeDidJwkFromPublic();
    headerOptions = { header: { kid, alg: "ES256", typ: "vc+sd-jwt" } };
  }

  const now = new Date();
  const expiryDate = new Date(now);
  expiryDate.setMonth(now.getMonth() + 6);
  // Compute issuer DID for payload
  let issuerDidForPayload;
  if (isHaip || process.env.ISSUER_SIGNATURE_TYPE === "x509") {
    issuerDidForPayload = serverURL;
  } else if (sessionObject.signatureType === "did:web") {
    issuerDidForPayload = computeDidWebFromServer().did;
  } else {
    issuerDidForPayload = computeDidJwkFromPublic().did;
  }
  // Issue credential
  const credential = await sdjwt.issue(
    {
      iss: issuerDidForPayload,
      iat: Math.floor(Date.now() / 1000),
      nbf: Math.floor(Date.now() / 1000),
      exp: Math.floor(expiryDate.getTime() / 1000),
      vct: credType,
      ...credPayload.claims,
      cnf,
    },
    credPayload.disclosureFrame,
    headerOptions
  );

  return credential;
}
