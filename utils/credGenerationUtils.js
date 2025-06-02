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
  IssuerSignedDocument,
} from "@m-doc/mdl";
import {
  createSign,
  createPrivateKey,
  createHash,
  randomBytes,
} from "crypto";
import { Buffer } from "buffer";

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

// Helper functions for mDL generation

// Convert PEM to DER ArrayBuffer (Node.js)
function pemToDerArrayBufferNode(pem) {
  if (!pem) return null;
  const b64 = pem.replace(/(-----(BEGIN|END)[\w\s]+-----|[\n\r])/g, "");
  return Buffer.from(b64, "base64").buffer;
}

// Convert JWK to a COSE Key Map structure (simplified)
// Note: @m-doc/mdl might offer a utility like coseFromJwk which should be preferred
function jwkToCoseKeyMap(jwk) {
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
    console.warn("Unsupported or incomplete JWK for COSE conversion:", jwk);
    // Depending on mDL requirements, may need to throw error or return specific empty structure
    return new Map(); 
  }
  const coseKey = new Map();
  coseKey.set(1, 2); // kty: EC2 (Elliptic Curve Keys)
  coseKey.set(-1, 1); // crv: P-256
  coseKey.set(-2, Buffer.from(jwk.x, "base64url")); // x-coordinate
  coseKey.set(-3, Buffer.from(jwk.y, "base64url")); // y-coordinate
  return coseKey;
}

function generateRandomBytesSyncForMdl(length) {
  return randomBytes(length).buffer;
}

async function sha256HasherForMdl(data /*: ArrayBuffer */) {
  const hash = createHash("sha256");
  hash.update(Buffer.from(data));
  return hash.digest().buffer;
}

// Creates a signer for mDL's signIssuerAuth
async function createMdlSignerForKey(
  signatureType, // "x509" or "jwk"
  isHaip, // boolean
  // For X.509
  x509PrivateKeyPem,
  // For JWK
  jwkPrivateKeyPem // e.g., content of private-key.pem
) {
  let nodePrivateKey;
  const alg = "ES256"; // mDL typically uses ES256 with P-256 keys

  const effectiveSignatureType =
    (isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509") ||
    signatureType === "x509"
      ? "x509"
      : "jwk";

  if (effectiveSignatureType === "x509") {
    if (!x509PrivateKeyPem) throw new Error("X.509 private key PEM is required for mDL signing.");
    nodePrivateKey = createPrivateKey(x509PrivateKeyPem);
  } else { // jwk
    if (!jwkPrivateKeyPem) throw new Error("JWK private key PEM is required for mDL signing.");
    const privateJwk = pemToJWK(jwkPrivateKeyPem, "private"); // pemToJWK is from cryptoUtils
    nodePrivateKey = createPrivateKey({ key: privateJwk, format: "jwk" });
  }

  return {
    sign: async (dataToSign /*: ArrayBuffer */) => {
      const signInstance = createSign("SHA256"); // ES256 uses SHA256 hash
      signInstance.update(Buffer.from(dataToSign));
      const signature = signInstance.sign({
        key: nodePrivateKey,
        dsaEncoding: "ieee-p1363", // For raw r||s signature format
      });
      return signature.buffer;
    },
    alg: alg,
    // x5c: if effectiveSignatureType is 'x509', the cert could be here or passed to signIssuerAuth
  };
}

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

  if (
    process.env.ISSUER_SIGNATURE_TYPE === "x509" ||
    sessionObject.signatureType === "x509" ||
    sessionObject.isHaip
  ) {
    console.log("x509 signature type");
    ({ signer, verifier } = await createSignerVerifierX509(
      privateKeyPemX509,
      certificatePemX509
    ));
  } else {
    console.log("jwk signature type");
    ({ signer, verifier } = await createSignerVerifier(
      pemToJWK(privateKey, "private"),
      pemToJWK(publicKeyPem, "public")
    ));
  }

  console.log("vc+sd-jwt ", vct);

  if (!requestBody.proof || !requestBody.proof.jwt) {
    const error = new Error("proof not found");
    error.status = 400;
    throw error;
  }

  const decodedWithHeader = jwt.decode(requestBody.proof.jwt, {
    complete: true,
  });
  const holderJWKS = decodedWithHeader.header;

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

  // Handle holder binding
  let cnf = { jwk: holderJWKS.jwk };
  if (!cnf.jwk) {
    cnf = { jwk: await didKeyToJwks(holderJWKS.kid) };
  }

  // Prepare issuance headers
  const headerOptions =
    (sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509") ||
    sessionObject.signatureType === "x509"
      ? {
          header: {
            x5c: [pemToBase64Der(certificatePemX509)],
          },
        }
      : {
          header: {
            kid: "aegean#authentication-key",
          },
        };

  const now = new Date();
  const expiryDate = new Date(now);
  expiryDate.setMonth(now.getMonth() + 6);
  // Issue credential
  const credential = await sdjwt.issue(
    {
      iss: serverURL,
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

  // console.log("Credential issued: ", credential);

  if (format === "vc+sd-jwt") {
    console.log("Credential issued: ", credential);
    return credential;
    // format: "vc+sd-jwt",
    // c_nonce: generateNonce(),
    // c_nonce_expires_in: 86400,
  }
  if (format === "mDL" || format === "mdl") {
    console.log("Attempting to generate mDL credential...");
    try {
      const mdlSignerInstance = await createMdlSignerForKey(
        sessionObject.signatureType, // "x509" or "jwk"
        sessionObject.isHaip,
        privateKeyPemX509, // x509 private key
        privateKey // jwk private key (loaded from private-key.pem)
      );

      const mDLClaimsMapped = mapClaimsToMdl(credPayload.claims, vct);

      const issuedDocument = new IssuerSignedDocument({
        docType: DOC_TYPE_MDL,
      });

      // Add claims to the default mDL namespace
      await issuedDocument.addNamespace(
        DEFAULT_MDL_NAMESPACE,
        mDLClaimsMapped,
        generateRandomBytesSyncForMdl
      );
      
      const holderJwkForDeviceKey = holderJWKS.jwk ? await jwkToCoseKeyMap(holderJWKS.jwk) : new Map();
      
      const msoOptions = {
         // deviceKey expects a COSE_Key structure. jwkToCoseKeyMap provides a Map.
         // If @m-doc/mdl provides coseFromJwk, use: coseFromJwk(holderJWKS.jwk)
        deviceKey: holderJwkForDeviceKey, 
      };

      let otherProtectedHeaders = new Map();
      let otherUnprotectedHeaders = new Map();
      let issuerCertificateDer;

      const effectiveSignatureType =
        (sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509") ||
        sessionObject.signatureType === "x509"
          ? "x509"
          : "jwk";

      if (effectiveSignatureType === "x509") {
        issuerCertificateDer = pemToDerArrayBufferNode(certificatePemX509);
        if (issuerCertificateDer) {
          // COSE header for x5c chain is 33
          otherProtectedHeaders.set(33, [issuerCertificateDer]); 
        }
        // For X.509, a kid might be derived from cert, or not used if x5c is present
      } else { // JWK
        if(headerOptions.header.kid) {
            otherUnprotectedHeaders.set(4, Buffer.from(headerOptions.header.kid, 'utf-8')); // COSE kid is label 4
        }
      }
      
      // Validity information
      const mDLValidityInfo = {
        signed: now, // current date object
        validFrom: now, // current date object
        validUntil: expiryDate, // expiry date object
      };

      await issuedDocument.signIssuerAuth(
        { alg: mdlSignerInstance.alg, signer: mdlSignerInstance.sign }, // Corrected structure
        { digestAlgorithm: "SHA-256", hasher: sha256HasherForMdl }, // Hash options
        mDLValidityInfo, // Validity info
        msoOptions, // Device key options (for MSO)
        otherProtectedHeaders, // Other protected headers (e.g., x5c)
        otherUnprotectedHeaders // Other unprotected headers (e.g., kid for JWK)
      );

      const mobileDocument = new MDoc({
        documents: [issuedDocument],
      });

      const encodedMobileDocument = mobileDocument.encode(); // Returns ArrayBuffer
      // Convert to hex or base64url for transmission
      const encodedMobileDocumentHex = Buffer.from(encodedMobileDocument).toString("hex");
      
      console.log("mDL Credential generated (hex):", encodedMobileDocumentHex.substring(0,100) + "..."); // Log snippet
      return encodedMobileDocumentHex;

    } catch (error) {
      console.error("Error generating mDL credential:", error);
      // Fallback or re-throw, depending on desired behavior
      // For now, re-throwing to make it visible
      throw new Error(`Failed to generate mDL: ${error.message}`);
    }
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

  if (!requestBody.proof || !requestBody.proof.jwt) {
    const error = new Error("proof not found");
    error.status = 400;
    throw error;
  }

  const decodedWithHeader = jwt.decode(requestBody.proof.jwt, {
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

  // Handle holder binding
  let cnf = { jwk: holderJWKS.jwk };
  if (!cnf.jwk) {
    cnf = { jwk: await didKeyToJwks(holderJWKS.kid) };
  }

  // Prepare issuance headers
  const headerOptions = isHaip
    ? {
        header: {
          x5c: [pemToBase64Der(certificatePemX509)],
        },
      }
    : {
        header: {
          kid: "aegean#authentication-key",
        },
      };

  const now = new Date();
  const expiryDate = new Date(now);
  expiryDate.setMonth(now.getMonth() + 6);
  // Issue credential
  const credential = await sdjwt.issue(
    {
      iss: serverURL,
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
