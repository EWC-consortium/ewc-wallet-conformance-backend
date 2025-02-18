import jwt from "jsonwebtoken";
import {
  createSignerVerifier,
  digest,
  generateSalt,
  createSignerVerifierX509,
  pemToBase64Der,
} from "./utils/sdjwtUtils.js";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";

import {
    createPIDPayload,
    createStudentIDPayload,
    getPIDSDJWTData,
    getStudentIDSDJWTData,
    getGenericSDJWTData,
    getEPassportSDJWTData,
    createEPassportPayload,
    getVReceiptSDJWTData,
    getVReceiptSDJWTDataWithPayload,
    createPaymentWalletAttestationPayload,
    createPhotoIDAttestationPayload,
    getFerryBoardingPassSDJWTData,
    createPCDAttestationPayload,
  } from "../utils/credPayloadUtil.js";




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

async function handleVcSdJwtFormat(requestBody, sessionObject, serverURL) {
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
      credPayload = createPaymentWalletAttestationPayload();
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
      credPayload = createPhotoIDAttestationPayload();
      break;
    case "eu.europa.ec.eudi.pcd.1":
      credPayload = createPCDAttestationPayload();
      break;
    default:
      throw new Error(`Unsupported credential type: ${credType}`);
  }

  // Handle holder binding
  let cnf = { jwk: holderJWKS.jwk };
  if (!cnf.jwk) {
    cnf = await didKeyToJwks(holderJWKS.kid);
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

  // Issue credential
  const credential = await sdjwt.issue(
    {
      iss: serverURL,
      iat: Math.floor(Date.now() / 1000),
      vct: credType,
      ...credPayload.claims,
      cnf,
    },
    credPayload.disclosureFrame,
    headerOptions
  );

  return {
    format: "vc+sd-jwt",
    credential,
    c_nonce: generateNonce(),
    c_nonce_expires_in: 86400,
  };
}
