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

import { encode as cborEncode, decode as cborDecode} from 'cbor-x';  
import cbor from 'cbor'; 
//  import  diagnose from 'cbor';          // npm i cbor  (same package the spec uses)


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
  getPIDSDJWTDataMsoMdoc,
  getLoyaltyCardSDJWTDataWithPayload,
} from "../utils/credPayloadUtil.js";

import issuerConfig from "../data/issuer-config.json" assert { type: "json" };

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

// const issuerConfig = require("../data/issuer-config.json");

// Convert DER signature to IEEE P1363 format (raw r,s values) for COSE
function derToP1363(derSignature) {
  // DER signature format parsing
  // DER: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
  
  if (derSignature[0] !== 0x30) {
    throw new Error('Invalid DER signature format');
  }
  
  let offset = 2; // Skip 0x30 and total length
  
  // Read R value
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature format - R not found');
  }
  offset++;
  const rLength = derSignature[offset];
  offset++;
  let rValue = derSignature.slice(offset, offset + rLength);
  offset += rLength;
  
  // Read S value
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature format - S not found');
  }
  offset++;
  const sLength = derSignature[offset];
  offset++;
  let sValue = derSignature.slice(offset, offset + sLength);
  
  // Remove leading zeros but ensure 32 bytes for each value (ES256)
  if (rValue.length > 32) {
    rValue = rValue.slice(rValue.length - 32);
  } else if (rValue.length < 32) {
    const padding = Buffer.alloc(32 - rValue.length);
    rValue = Buffer.concat([padding, rValue]);
  }
  
  if (sValue.length > 32) {
    sValue = sValue.slice(sValue.length - 32);
  } else if (sValue.length < 32) {
    const padding = Buffer.alloc(32 - sValue.length);
    sValue = Buffer.concat([padding, sValue]);
  }
  
  // Concatenate r and s for IEEE P1363 format
  return Buffer.concat([rValue, sValue]);
}

// Maps claims from existing payload to mso_mdoc format
// This is a simplified mapper and needs to be extended for different VCTs
function mapClaimsToMsoMdoc(claims, vct) {
  const msoMdocClaims = { ...claims }; // Start by copying all claims

  // mDL uses 'birth_date', SD-JWT might use 'birthdate'
  if (claims.birthdate) {
    msoMdocClaims.birth_date = claims.birthdate;
    delete msoMdocClaims.birthdate; // remove original to avoid duplication
  } else if (claims.birth_date) {
    msoMdocClaims.birth_date = claims.birth_date;
  }

  // mDL 'issue_date' and 'expiry_date' for the document itself
  if (claims.issuance_date) {
    msoMdocClaims.issue_date = claims.issuance_date; // Map PID's issuance_date
    delete msoMdocClaims.issuance_date;
  } else if (claims.issue_date) {
    msoMdocClaims.issue_date = claims.issue_date;
  }

  if (claims.expiry_date) {
    msoMdocClaims.expiry_date = claims.expiry_date; // Map PID's expiry_date
  }

  // Placeholder for other claims and VCT specific mappings
  // For example, for a driver's license (mDL docType):
  // if (vct === 'some_driver_license_vct') {
  //   msoMdocClaims.driving_privileges = claims.driving_privileges;
  //   msoMdocClaims.portrait = claims.portrait; // Needs to be bytes
  //   msoMdocClaims.document_number = claims.document_number;
  //   msoMdocClaims.issuing_country = claims.issuing_country;
  // }

  if (
    claims.unique_id &&
    (vct === "VerifiablePIDSDJWT" || vct === "urn:eu.europa.ec.eudi:pid:1")
  ) {
    msoMdocClaims.unique_identifier = claims.unique_id; // Example mapping for PID
    delete msoMdocClaims.unique_id;
  }

  // Add more specific mappings based on vct and mDL data element definitions
  // console.log("Mapped mDL claims:", msoMdocClaims);
  return msoMdocClaims;
}

const DOC_TYPE_MDL = "org.iso.18013.5.1.mDL";
const DEFAULT_MDL_NAMESPACE = "org.iso.18013.5.1";

export async function handleCredentialGenerationBasedOnFormat(
  requestBody,
  sessionObject,
  serverURL,
  format="vc+sd-jwt"
) {
  const vct = requestBody.vct;

  let signer, verifier;
  let headerOptions; // Define headerOptions here to be populated based on sig type

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
      },
    };
  } else { // Covers "jwk" and "kid-jwk"
    const publicJwkForSigning = pemToJWK(publicKeyPem, "public");
    ({ signer, verifier } = await createSignerVerifier(
      pemToJWK(privateKey, "private"),
      publicJwkForSigning
    ));

    let joseHeader = {};
    if (effectiveSignatureType === "jwk") {
      console.log("jwk signature type selected: Using embedded JWK in header.");
      joseHeader = { 
        jwk: publicJwkForSigning,
        alg: "ES256" // Algorithm must be specified when jwk is used in header
      };
    } else if (effectiveSignatureType === "kid-jwk") { // Assuming "kid-jwk" as the type for kid-based JWK signing
      console.log(`kid-jwk signature type selected: Using KID: ${defaultSigningKid} in header.`);
      joseHeader = { 
        kid: defaultSigningKid,
        alg: "ES256" // alg is also typically included with kid for clarity, though not strictly required by RFC7515 if kid is enough for resolution
      };
    } else if (effectiveSignatureType === "did:web") {
      console.log("did:web signature type selected.");
      const proxyPath = process.env.PROXY_PATH || null;
      let controller = serverURL;
      if (proxyPath) {
        controller = serverURL.replace("/"+proxyPath,"") + ":" + proxyPath;
      }
      controller = controller.replace("https://","").replace("http://","");
      const kid = `did:web:${controller}#keys-1`;
      console.log(`Using KID: ${kid} for did:web signing.`);
      joseHeader = { 
        kid: kid,
        alg: "ES256"
      };
    } else {
      // Fallback or default if signatureType is something else (e.g., a generic 'jwk' without specific instruction)
      // For now, defaulting to KID if not explicitly 'jwk' for direct embedding.
      // This matches the previous default behavior when jwkHeaderPreference was 'kid'.
      console.warn(`Unspecified or unrecognized JWK signature type '${effectiveSignatureType}', defaulting to KID: ${defaultSigningKid}.`);
      joseHeader = { 
        kid: defaultSigningKid,
        alg: "ES256"
      };
    }
    headerOptions = { header: joseHeader };
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
    case "PhotoID":
      credPayload = createPhotoIDAttestationPayload(issuerName);
      break;
    case "eu.europa.ec.eudi.pcd.1":
      credPayload = createPCDAttestationPayload(issuerName);
      break;
    case "urn:eu.europa.ec.eudi:pid:1:mso_mdoc":
      // TODO update this for mso_mdoc
      credPayload = getPIDSDJWTDataMsoMdoc();
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
    const keys = await didKeyToJwks(holderJWKS.kid);
    cnf = {jwk: keys.keys[0]};
  }

  const now = new Date();
  const expiryDate = new Date(now);
  expiryDate.setMonth(now.getMonth() + 6);

  if (format === "jwt_vc_json") {
    console.log("Issuing a jwt_vc format credential");
    const vcPayload = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential", vct],
      credentialSubject: credPayload.claims,
      issuer: serverURL,
      issuanceDate: now.toISOString(),
      expirationDate: expiryDate.toISOString(),
    };

    const jwtPayload = {
      iss: serverURL,
      iat: Math.floor(now.getTime() / 1000),
      nbf: Math.floor(now.getTime() / 1000),
      exp: Math.floor(expiryDate.getTime() / 1000),
      vc: vcPayload,
      cnf: cnf,
    };

    const privateKeyForSigning =
      effectiveSignatureType === "x509" ? privateKeyPemX509 : privateKey;

    const signOptions = {
      algorithm: "ES256",
      ...headerOptions,
    };

    const credential = jwt.sign(jwtPayload, privateKeyForSigning, signOptions);
    return credential;
  } else if (format === "dc+sd-jwt") {
    console.log("Issuing a dc+sd-jwt format credential");
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
    console.log("Credential issued: ", credential);
    return credential;
  } else if (format === "mDL" || format === "mdl") {
    console.log("Attempting to generate mDL credential using manual CBOR construction...");
    try {
     
      const credentialConfiguration =
        issuerConfig.credential_configurations_supported[vct];
      if (!credentialConfiguration) {
        throw new Error(`Configuration not found for VCT: ${vct}`);
      }

      const docType = credentialConfiguration.doctype;
      if (!docType) {
        throw new Error(`'doctype' not defined for VCT: ${vct}`);
      }
      const namespace = docType;

      const claims = credPayload;
      const msoMdocClaims = claims.claims[namespace];
      
      if (!msoMdocClaims) {
        throw new Error(`Claims not found under namespace '${namespace}' for VCT: ${vct}. Available namespaces: ${Object.keys(claims.claims || {}).join(', ')}`);
      }

      const currentEffectiveSignatureType =
      (sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509") || sessionObject.signatureType === "x509"
      ? "x509"
      : "jwk";

      const mDLClaimsMapped = mapClaimsToMsoMdoc(msoMdocClaims, vct);
      
      const devicePublicKeyJwk = cnf.jwk;
      let issuerPrivateKeyForSign, issuerCertificateForSign;
      
      if (currentEffectiveSignatureType === "x509") {
        console.log("Using X.509 for mDL signing.");
        issuerPrivateKeyForSign = privateKeyPemX509; // Use PEM string directly for crypto operations
        issuerCertificateForSign = certificatePemX509;
      } else {
        console.log("Using JWK for mDL signing.");
        issuerPrivateKeyForSign = privateKeyPemX509; // Use PEM string directly for crypto operations
        issuerCertificateForSign = certificatePemX509;
      }
      
      // Create individual claim items manually
      const standardNamespace = namespace//"org.iso.18013.5.1";
      const nameSpaceItems = [];
      const valueDigests = {};
      valueDigests[namespace] = {};
      
      Object.entries(mDLClaimsMapped).forEach(([key, value], index) => {
        // Create the IssuerSignedItem structure manually
        const randomBytes = cryptoModule.randomBytes(16);
        const issuerSignedItem = {
          digestID: index,
          random: randomBytes,
          elementIdentifier: key,
          elementValue: value
        };
        
        // Encode the item as CBOR using cbor library
        const encodedItem = cbor.encode(issuerSignedItem);
        
        // Calculate digest on the encoded item
        const hash = cryptoModule.createHash('sha256');
        hash.update(encodedItem);
        valueDigests[namespace][index] = hash.digest();
        
        // Create tag 24 with the encoded CBOR bytes for proper 24(<<{...}>>) structure
        const taggedItem = new cbor.Tagged(24, encodedItem);
        nameSpaceItems.push(taggedItem);
        
        // console.log(`Added claim: ${key} = ${value} (digestID: ${index})`);
      });
      
      // Create the issuerSigned structure manually
      const issuerSignedData = {
        nameSpaces: {},
        issuerAuth: null // Will be populated during signing
      };
      
      // Set the namespace with our manually created items
      issuerSignedData.nameSpaces[namespace] = nameSpaceItems;
      
      // console.log("Manual nameSpaces structure:", Object.keys(issuerSignedData.nameSpaces));
      // console.log(`${namespace} contains ${nameSpaceItems.length} items`);
      
      // Create the Mobile Security Object (MSO) manually
      const validityInfo = {
        signed: new Date().toISOString(),
        validFrom: new Date().toISOString(),
        validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      };
      
      const mobileSecurityObject = {
        version: "1.0",
        digestAlgorithm: "SHA-256",
        valueDigests: valueDigests,
        deviceKeyInfo: {
          deviceKey: devicePublicKeyJwk
        },
        docType: docType,
        validityInfo: validityInfo
      };
      
      // Encode the MSO using cbor library and keep as raw Buffer 
      const encodedMSO = cbor.encode(mobileSecurityObject);
      
      // Create proper COSE Sign1 structure for issuerAuth
      // COSE Sign1 format: [protected, unprotected, payload, signature]
      
      // Critical fix: Use JavaScript Map with actual integer keys for COSE headers
      // This is the key to fixing the COSE label validation errors
      
      // Protected headers (must be a bstr containing encoded CBOR map)
      const protectedHeadersMap = new Map();
      protectedHeadersMap.set(1, -7); // alg: ES256 (COSE algorithm identifier) - use actual integer 1
      const encodedProtectedHeaders = cbor.encode(protectedHeadersMap);
      
      // Unprotected headers (CBOR map, not encoded)  
      const unprotectedHeadersMap = new Map();
      unprotectedHeadersMap.set(33, Buffer.from(pemToBase64Der(issuerCertificateForSign), 'base64')); // x5c: certificate chain - use actual integer 33
      
      // Create COSE_Sign1 structure to sign 
      // The MSO should be the payload that gets signed
      const toBeSigned = cbor.encode([
        "Signature1", // context string for Sign1
        encodedProtectedHeaders, // protected headers as bstr
        Buffer.alloc(0), // external_aad (empty) - use Buffer instead of Uint8Array for consistency
        encodedMSO // payload (MSO to be signed)
      ]);
      
      // Create actual signature using the private key
      const sign = cryptoModule.createSign('SHA256');
      sign.update(toBeSigned);
      const derSignature = sign.sign(issuerPrivateKeyForSign);
      
      // Convert DER signature to IEEE P1363 format (raw r,s values) for COSE
      // ES256 signature should be 64 bytes (32 bytes r + 32 bytes s)
      const signature = derToP1363(derSignature);
      
      // Create the COSE Sign1 structure that will be the issuerAuth
      // Use the encoded MSO directly as the payload 
      const coseSign1 = [
        encodedProtectedHeaders, // protected headers as bstr
        unprotectedHeadersMap, // unprotected headers as map (this will preserve integer keys)
        encodedMSO, // payload (MSO encoded as CBOR bytes)
        signature // signature
      ];
      
      // The issuerAuth IS the COSE Sign1 structure
      const issuerAuth = coseSign1;
      
      issuerSignedData.issuerAuth = issuerAuth;
      
      // Encode the complete IssuerSigned structure using cbor library consistently
      const finalIssuerSigned = cbor.encode(issuerSignedData);
      
      
      
      const encodedMobileDocument = Buffer.from(finalIssuerSigned).toString("base64url");
      console.log("Manual mDL Credential generated (base64url):", encodedMobileDocument);

      return encodedMobileDocument;
    } catch (error) {
      console.error("Error in manual mDL construction:", error);
      throw new Error(`Failed to generate mDL manually: ${error.message}`);
    }
  } else {
    throw new Error(`Unsupported format: ${format}`);
  }
}

export async function handleCredentialGenerationBasedOnFormatDeferred(sessionObject, serverURL) {
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
