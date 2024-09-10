import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  base64UrlEncodeSha256,
} from "../utils/cryptoUtils.js";
import {
  buildAccessToken,
  generateRefreshToken,
  buildIdToken,
} from "../utils/tokenUtils.js";

import {
  getAuthCodeSessions,
  getPreCodeSessions,
} from "../services/cacheService.js";

import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import {
  createSignerVerifier,
  digest,
  generateSalt,
} from "../utils/sdjwtUtils.js";
import jwt from "jsonwebtoken";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { request } from "http";

const router = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

console.log("privateKey");
console.log(privateKey);

///pre-auth flow sd-jwt
router.get(["/offer"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const preSessions = getPreCodeSessions();
  if (preSessions.sessions.indexOf(uuid) < 0) {
    preSessions.sessions.push(uuid);
    preSessions.results.push({ sessionId: uuid, status: "pending" });
  }

  // console.log("active sessions");
  // console.log(issuanceResults);
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer/${uuid}`; //OfferUUID

  let code = qr.image(credentialOffer, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  res.json({
    qr: encodedQR,
    deepLink: credentialOffer,
    sessionId: uuid,
  });
});

//pre-auth flow request sd-jwt
router.get(["/credential-offer/:id"], (req, res) => {
  res.json({
    credential_issuer: serverURL,
    credentials: ["VerifiablePortableDocumentA1"],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": req.params.id,
        user_pin_required: true,
      },
    },
  });
});

// ***************
///pre-auth flow jwt_vc_json
router.get(["/pre-offer-jwt"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const preSessions = getPreCodeSessions();
  if (preSessions.sessions.indexOf(uuid) < 0) {
    preSessions.sessions.push(uuid);
    preSessions.results.push({ sessionId: uuid, status: "pending" });
  }
  let credentialOffer = `openid-credential-offer://?credential_offer_uri=${serverURL}/credential-offer-pre-jwt/${uuid}`; //OfferUUID
  let code = qr.image(credentialOffer, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  res.json({
    qr: encodedQR,
    deepLink: credentialOffer,
    sessionId: uuid,
  });
});

//pre-auth flow request sd-jwt
router.get(["/credential-offer-pre-jwt/:id"], (req, res) => {
  res.json({
    credential_issuer: serverURL,
    credentials: ["VerifiablePortableDocumentA2"],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": req.params.id,
        user_pin_required: true,
      },
    },
  });
});

function getPersonaPart(inputString) {
  const personaKey = "persona=";
  const personaIndex = inputString.indexOf(personaKey);

  if (personaIndex === -1) {
    return null; // "persona=" not found in the string
  }

  // Split the string based on "persona="
  const parts = inputString.split(personaKey);

  // Return the part after "persona="
  return parts[1] || null;
}

router.post("/token_endpoint", async (req, res) => {
  //pre-auth code flow
  const grantType = req.body.grant_type;
  const preAuthorizedCode = req.body["pre-authorized_code"]; // req.body["pre-authorized_code"]
  const userPin = req.body["user_pin"];
  //code flow
  const code = req.body["code"]; //TODO check the code ...
  const code_verifier = req.body["code_verifier"];
  const redirect_uri = req.body["redirect_uri"];

  // console.log("token_endpoint parameters received");
  // console.log(grantType);
  // console.log(preAuthorizedCode);
  // console.log(userPin);
  // console.log("---------");

  let generatedAccessToken = buildAccessToken(serverURL, privateKey);

  if (grantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
    console.log("pre-auth code flow");
    const preSessions = getPreCodeSessions();
    let index = preSessions.sessions.indexOf(preAuthorizedCode);
    if (index >= 0) {
      console.log(
        `credential for session ${preAuthorizedCode} has been issued`
      );
      preSessions.results[index].status = "success";
      preSessions.accessTokens[index] = generatedAccessToken;

      let personaId = getPersonaPart(preAuthorizedCode);
      if (personaId) {
        preSessions.personas[index] = personaId;
      } else {
        preSessions.personas[index] = null;
      }

      // console.log("pre-auth code flow" + preSessions.results[index].status);
    }
  } else {
    if (grantType == "authorization_code") {
      const codeSessions = getAuthCodeSessions();
      validatePKCE(
        codeSessions.requests,
        code,
        code_verifier,
        codeSessions.results
      );
    }
  }
  //TODO return error if code flow validation fails and is not a pre-auth flow
  res.json({
    access_token: generatedAccessToken,
    refresh_token: generateRefreshToken(),
    token_type: "bearer",
    expires_in: 86400,
    id_token: buildIdToken(serverURL, privateKey),
    c_nonce: generateNonce(),
    c_nonce_expires_in: 86400,
  });
});

router.post("/credential", async (req, res) => {
  // console.log("7 ROUTE /credential CALLED!!!!!!");
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Split "Bearer" and the token
  // Accessing the body data
  const requestBody = req.body;
  const format = requestBody.format;
  const requestedCredentials = requestBody.credential_definition
    ? requestBody.credential_definition.type
    : null; //removed requestBody.types to conform to RFC001
  //TODO valiate bearer header
  let decodedWithHeader;
  let decodedHeaderSubjectDID;
  if (requestBody.proof && requestBody.proof.jwt) {
    // console.log(requestBody.proof.jwt)
    decodedWithHeader = jwt.decode(requestBody.proof.jwt, { complete: true });
    // console.log(decodedWithHeader.payload.iss);
    decodedHeaderSubjectDID = decodedWithHeader.payload.iss;
  }

  // console.log(credential);
  if (format === "jwt_vc_json") {
    let payload = {};
    if (requestedCredentials != null && requestedCredentials[0] === "PID") {
      //get persona if existing from accessToken
      const preSessions = getPreCodeSessions();
      let persona = getPersonaFromAccessToken(
        token,
        preSessions.personas,
        preSessions.accessTokens
      );

      let credentialSubject = {
        id: decodedHeaderSubjectDID,
        family_name: "Doe",
        given_name: "John",
        birth_date: "1990-01-01",
        age_over_18: true,
        issuance_date: new Date(
          Math.floor(Date.now() / 1000) * 1000
        ).toISOString(),
        expiry_date: new Date(
          Math.floor(Date.now() + 60 / 1000) * 1000
        ).toISOString(),
        issuing_authority: "https://authority.example.com",
        issuing_country: "GR",
      };
      if (persona === "1") {
        credentialSubject = {
          id: decodedHeaderSubjectDID,
          family_name: "Conti",
          given_name: "Mario",
          birth_date: "1988-11-12",
          age_over_18: true,
          issuance_date: new Date(
            Math.floor(Date.now() / 1000) * 1000
          ).toISOString(),
          expiry_date: new Date(
            Math.floor(Date.now() + 60 / 1000) * 1000
          ).toISOString(),
          issuing_authority: "https://authority.example.com",
          issuing_country: "IT",
        };
      } else if (persona === "2") {
        credentialSubject = {
          id: decodedHeaderSubjectDID,
          family_name: "Matkalainen",
          given_name: "Hannah",
          birth_date: "2005-02-07",
          age_over_18: true,
          issuance_date: new Date(
            Math.floor(Date.now() / 1000) * 1000
          ).toISOString(),
          expiry_date: new Date(
            Math.floor(Date.now() + 60 / 1000) * 1000
          ).toISOString(),
          issuing_authority: "https://authority.example.com",
          issuing_country: "FI",
        };
      } else if (persona === "3") {
        credentialSubject = {
          id: decodedHeaderSubjectDID,
          family_name: "Fischer",
          given_name: "Felix",
          birth_date: "1953-01-23",
          age_over_18: true,
          issuance_date: new Date(
            Math.floor(Date.now() / 1000) * 1000
          ).toISOString(),
          expiry_date: new Date(
            Math.floor(Date.now() + 60 / 1000) * 1000
          ).toISOString(),
          issuing_authority: "https://authority.example.com",
          issuing_country: "FI",
        };
      }

      payload = {
        iss: serverURL,
        sub: decodedHeaderSubjectDID || "",
        exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
        iat: Math.floor(Date.now() / 1000), // Token issued at time
        // nbf: Math.floor(Date.now() / 1000),
        jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
        vc: {
          credentialSubject: credentialSubject,
          expirationDate: new Date(
            (Math.floor(Date.now() / 1000) + 60 * 60) * 1000
          ).toISOString(),
          id: decodedHeaderSubjectDID,
          issuanceDate: new Date(
            Math.floor(Date.now() / 1000) * 1000
          ).toISOString(),
          issued: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
          issuer: serverURL,
          type: ["PID"],
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://europa.eu/2018/credentials/eudi/pid/v1",
          ],
          issuer: serverURL,
          validFrom: new Date(
            Math.floor(Date.now() / 1000) * 1000
          ).toISOString(),
        },
        // Optional claims
      };
    } else {
      if (
        requestedCredentials != null &&
        requestedCredentials[0] === "ePassportCredential"
      ) {
        payload = {
          iss: serverURL,
          sub: decodedHeaderSubjectDID || "",
          iat: Math.floor(Date.now() / 1000), // Token issued at time
          exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
          jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
          vc: {
            credentialSubject: {
              id: decodedHeaderSubjectDID || "", // Replace with the actual subject DID
              electronicPassport: {
                dataGroup1: {
                  birthdate: "1990-01-01",
                  docTypeCode: "P",
                  expiryDate: "2030-01-01",
                  genderCode: "M",
                  holdersName: "John Doe",
                  issuerCode: "GR",
                  natlText: "Hellenic",
                  passportNumberIdentifier: "123456789",
                },
                dataGroup15: {
                  activeAuthentication: {
                    publicKeyBinaryObject: "somePublicKeyUri",
                  },
                },
                dataGroup2EncodedFaceBiometrics: {
                  faceBiometricDataEncodedPicture: "someBiometricUri",
                },
                digitalTravelCredential: {
                  contentInfo: {
                    versionNumber: 1,
                    signatureInfo: {
                      digestHashAlgorithmIdentifier: "SHA-256",
                      signatureAlgorithmIdentifier: "RS256",
                      signatureCertificateText: "someCertificateText",
                      signatureDigestResultBinaryObject: "someDigestResultUri",
                      signedAttributes: {
                        attributeTypeCode: "someTypeCode",
                        attributeValueText: "someValueText",
                      },
                    },
                  },
                  dataCapabilitiesInfo: {
                    dataTransferInterfaceTypeCode: "NFC",
                    securityAssuranceLevelIndText: "someSecurityLevel",
                    userConsentInfoText: "userConsentRequired",
                    virtualComponentPresenceInd: true,
                  },
                  dataContent: {
                    dataGroup1: {
                      birthdate: "1990-01-01",
                      docTypeCode: "P",
                      expiryDate: "2030-01-01",
                      genderCode: "M",
                      holdersName: "John Doe",
                      issuerCode: "GR",
                      natlText: "Hellenic",
                      passportNumberIdentifier: "123456789",
                      personalNumberIdentifier: "987654321",
                    },
                    dataGroup2EncodedFaceBiometrics: {
                      faceBiometricDataEncodedPicture: "someBiometricUri",
                    },
                    docSecurityObject: {
                      dataGroupHash: [
                        {
                          dataGroupNumber: 1,
                          valueBinaryObject: "someHashUri",
                        },
                      ],
                      digestHashAlgorithmIdentifier: "SHA-256",
                      versionNumber: 1,
                    },
                  },
                  docSecurityObject: {
                    dataGroupHash: [
                      {
                        dataGroupNumber: 1,
                        valueBinaryObject: "someHashUri",
                      },
                    ],
                    digestHashAlgorithmIdentifier: "SHA-256",
                    versionNumber: 1,
                  },
                },
              },
            },
            type: ["ePassportCredential"],
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://schemas.prod.digitalcredentials.iata.org/contexts/iata_credential.jsonld",
            ],
            issuer: serverURL,
            validFrom: new Date(
              Math.floor(Date.now() / 1000) * 1000
            ).toISOString(),
          },
        };
      } else {
        if (
          requestedCredentials != null &&
          requestedCredentials[0] === "EducationalID"
        ) {
          const preSessions = getPreCodeSessions();
          let persona = getPersonaFromAccessToken(
            token,
            preSessions.personas,
            preSessions.accessTokens
          );

          payload = {
            iss: serverURL,
            sub: decodedHeaderSubjectDID || "",
            iat: Math.floor(Date.now() / 1000), // Token issued at time
            exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
            jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
            vc: {
              type: ["EducationalID"],
              "@context": ["https://www.w3.org/2018/credentials/v1"],
              issuer: serverURL,
              credentialSubject: {
                id: decodedHeaderSubjectDID || "",
                identifier: "john.doe@university.edu",
                schacPersonalUniqueCode: [
                  "urn:schac:personalUniqueCode:int:esi:university.edu:12345",
                ],
                schacPersonalUniqueID: "urn:schac:personalUniqueID:us:12345",
                schacHomeOrganization: "university.edu",
                familyName: "Doe",
                firstName: "John",
                displayName: "John Doe",
                dateOfBirth: "1990-01-01",
                commonName: "Johnathan Doe",
                mail: "john.doe@university.edu",
                eduPersonPrincipalName: "john.doe@university.edu",
                eduPersonPrimaryAffiliation: "student",
                eduPersonAffiliation: ["member", "student"],
                eduPersonScopedAffiliation: ["student@university.edu"],
                eduPersonAssurance: [
                  "https://wiki.refeds.org/display/ASS/REFEDS+Assurance+Framework+ver+1.0",
                ],
              },
              issuanceDate: new Date(
                Math.floor(Date.now() / 1000) * 1000
              ).toISOString(),
              expirationDate: new Date(
                (Math.floor(Date.now() / 1000) + 60 * 60) * 1000
              ).toISOString(),
              validFrom: new Date(
                Math.floor(Date.now() / 1000) * 1000
              ).toISOString(),
            },
          };

          if (persona === "1") {
            payload.vc.credentialSubject = {
              id: decodedHeaderSubjectDID || "",
              identifier: "mario.conti@ewc.eu",
              schacPersonalUniqueCode: [
                "urn:schac:personalUniqueCode:int:esi:university.edu:12345",
              ],
              schacPersonalUniqueID: "urn:schac:personalUniqueID:us:12345",
              schacHomeOrganization: "university.edu",
              familyName: "Conti",
              firstName: "Mario",
              displayName: "Mario Conti",
              dateOfBirth: "1990-01-01",
              commonName: "Mario Contri",
              mail: "mario.conti@ewc.eu",
              eduPersonPrincipalName: "mario.conti@ewc.eu",
              eduPersonPrimaryAffiliation: "student",
              eduPersonAffiliation: ["member", "student"],
              eduPersonScopedAffiliation: ["student@ewc.eu"],
              eduPersonAssurance: [
                "https://wiki.refeds.org/display/ASS/REFEDS+Assurance+Framework+ver+1.0",
              ],
            };
          } else if (persona === "2") {
            payload.vc.credentialSubject = {
              id: decodedHeaderSubjectDID || "",
              identifier: "hannah@ewc.eu",
              schacPersonalUniqueCode: [
                "urn:schac:personalUniqueCode:int:esi:university.edu:12345",
              ],
              schacPersonalUniqueID: "urn:schac:personalUniqueID:us:12345",
              schacHomeOrganization: "university.edu",
              familyName: "Matkalainen",
              firstName: "Hannah",
              displayName: "Hannah Matkalainen",
              dateOfBirth: "1990-01-01",
              commonName: "Hannah Matkalainen",
              mail: "hannah@ewc.eu",
              eduPersonPrincipalName: "hannah@ewc.eu",
              eduPersonPrimaryAffiliation: "student",
              eduPersonAffiliation: ["member", "student"],
              eduPersonScopedAffiliation: ["student@ewc.eu"],
              eduPersonAssurance: [
                "https://wiki.refeds.org/display/ASS/REFEDS+Assurance+Framework+ver+1.0",
              ],
            };
          } else if (persona === "3") {
            payload.vc.credentialSubject = {
              id: decodedHeaderSubjectDID || "",
              identifier: "felix@ewc.eu",
              schacPersonalUniqueCode: [
                "urn:schac:personalUniqueCode:int:esi:university.edu:12345",
              ],
              schacPersonalUniqueID: "urn:schac:personalUniqueID:us:12345",
              schacHomeOrganization: "university.edu",
              familyName: "Fischer",
              firstName: "Felix",
              displayName: "Felix Fischer",
              dateOfBirth: "1990-01-01",
              commonName: "Felix Fischer",
              mail: "felix@ewc.eu",
              eduPersonPrincipalName: "felix@ewc.eu",
              eduPersonPrimaryAffiliation: "student",
              eduPersonAffiliation: ["member", "student"],
              eduPersonScopedAffiliation: ["student@ewc.eu"],
              eduPersonAssurance: [
                "https://wiki.refeds.org/display/ASS/REFEDS+Assurance+Framework+ver+1.0",
              ],
            };
          }
        } else {
          if (
            requestedCredentials != null &&
            requestedCredentials[0] === "allianceIDCredential"
          ) {
            payload = {
              iss: serverURL,
              sub: decodedHeaderSubjectDID || "",
              iat: Math.floor(Date.now() / 1000), // Token issued at time
              exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
              jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
              vc: {
                type: ["allianceIDCredential"],
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                issuer: serverURL,
                credentialSubject: {
                  id: decodedHeaderSubjectDID, // Replace with the actual subject DID
                  identifier: {
                    schemeID: "European Student Identifier",
                    value:
                      "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
                    id: "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
                  },
                },
                issuanceDate: new Date(
                  Math.floor(Date.now() / 1000) * 1000
                ).toISOString(),
                expirationDate: new Date(
                  (Math.floor(Date.now() / 1000) + 60 * 60) * 1000
                ).toISOString(),
                validFrom: new Date(
                  Math.floor(Date.now() / 1000) * 1000
                ).toISOString(),
              },
            };
          } else if (
            requestedCredentials != null &&
            requestedCredentials[0] === "ferryBoardingPassCredential"
          ) {
            const preSessions = getPreCodeSessions();
            let persona = getPersonaFromAccessToken(
              token,
              preSessions.personas,
              preSessions.accessTokens
            );

            payload = {
              iss: serverURL,
              sub: decodedHeaderSubjectDID || "",
              iat: Math.floor(Date.now() / 1000), // Token issued at time
              exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
              jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
              vc: {
                type: ["VerifiableCredential", "ferryBoardingPassCredential"],
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                issuer: serverURL,
                issuanceDate: new Date(
                  Math.floor(Date.now() / 1000) * 1000
                ).toISOString(),
                expirationDate: new Date(
                  (Math.floor(Date.now() / 1000) + 60 * 60) * 1000
                ).toISOString(),
                validFrom: new Date(
                  Math.floor(Date.now() / 1000) * 1000
                ).toISOString(),
                credentialSubject: {
                  id: decodedHeaderSubjectDID || "", // Replace with the actual subject DID
                  identifier: "John Doe",
                  ticketQR:
                    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHkAAAB5AQAAAAA+SX7VAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAABlUlEQVRIDe2YMUtCQRCFZxQVhQo2hdwV2NhZ+ggLFzcBrcNLYktjb2AiBBkDEtFiFE3d7WVo+BR+BX+gtEop3Rjb7ndmxmh8HTIz5TdvzZk5MhGoUZ1Hnz1swr3/ehyHt6nuKPexG5XQPeDqcgrBXT3wGso+ULuLoDr/owxPI27WqZLPKpFvH2FqESkBu8WqwCrCL3r6Ne3Slo6I0A9H/UUXH5KoJwUbPFLU5CJqsZubAiZwVLja4YpAyyKcijulVDrwjeMaLs5CmlgHds1GZc9K8T/AXTDwLB0yzhFb2CHavBtL68YRuBN3le6HB54Rz6MPGoNx7N2e3ws+b9YL2scQY8jI9iA9gN0FbgeEQLzUXwl90kpAmNyDe4SjH5itwbPfNRi7w0Ogl8KiB1QWUDZc0h34sFjDwrIs+w6GCSnNhWbzP9FAvVd8BzCgbChAkd4VnLQZX9VaQd9gM0b9D/UZoTQAAAABJRU5ErkJggg==",
                  ticketNumber: "ABC123456789",
                  ticketLet: "A",
                  lastName: "Doe",
                  firstName: "John",
                  seatType: "Economy",
                  seatNumber: "12A",
                  departureDate: "2023-11-30",
                  departureTime: "13:07:34",
                  arrivalDate: "2023-11-30",
                  arrivalTime: "15:30:00",
                  arrivalPort: "NYC",
                  vesselDescription: "Ferry XYZ",
                },
                
              },
            };
  
            if (persona === "1") {
              payload.vc.credentialSubject ={
                id: decodedHeaderSubjectDID || "", // Replace with the actual subject DID
                identifier: "Mario Conti",
                ticketQR:
                  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHkAAAB5AQAAAAA+SX7VAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAABlUlEQVRIDe2YMUtCQRCFZxQVhQo2hdwV2NhZ+ggLFzcBrcNLYktjb2AiBBkDEtFiFE3d7WVo+BR+BX+gtEop3Rjb7ndmxmh8HTIz5TdvzZk5MhGoUZ1Hnz1swr3/ehyHt6nuKPexG5XQPeDqcgrBXT3wGso+ULuLoDr/owxPI27WqZLPKpFvH2FqESkBu8WqwCrCL3r6Ne3Slo6I0A9H/UUXH5KoJwUbPFLU5CJqsZubAiZwVLja4YpAyyKcijulVDrwjeMaLs5CmlgHds1GZc9K8T/AXTDwLB0yzhFb2CHavBtL68YRuBN3le6HB54Rz6MPGoNx7N2e3ws+b9YL2scQY8jI9iA9gN0FbgeEQLzUXwl90kpAmNyDe4SjH5itwbPfNRi7w0Ogl8KiB1QWUDZc0h34sFjDwrIs+w6GCSnNhWbzP9FAvVd8BzCgbChAkd4VnLQZX9VaQd9gM0b9D/UZoTQAAAABJRU5ErkJggg==",
                ticketNumber: "3022",
                ticketLet: "Y",
                lastName: "Conti",
                firstName: "Mario",
                seatType: "Economy",
                seatNumber: "12A",
                departureDate: "2024-08-17",
                departureTime: "13:07:34",
                arrivalDate: "2024-08-17",
                arrivalTime: "15:30:00",
                arrivalPort: "MYKONOS TEST",
                vesselDescription: "MYKONOS TEST",
              }
            }else if(persona === "2"){
              payload.vc.credentialSubject ={
                id: decodedHeaderSubjectDID || "", // Replace with the actual subject DID
                identifier: "Hannah Matkalainen",
                ticketQR:
                  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHkAAAB5AQAAAAA+SX7VAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAABlUlEQVRIDe2YMUtCQRCFZxQVhQo2hdwV2NhZ+ggLFzcBrcNLYktjb2AiBBkDEtFiFE3d7WVo+BR+BX+gtEop3Rjb7ndmxmh8HTIz5TdvzZk5MhGoUZ1Hnz1swr3/ehyHt6nuKPexG5XQPeDqcgrBXT3wGso+ULuLoDr/owxPI27WqZLPKpFvH2FqESkBu8WqwCrCL3r6Ne3Slo6I0A9H/UUXH5KoJwUbPFLU5CJqsZubAiZwVLja4YpAyyKcijulVDrwjeMaLs5CmlgHds1GZc9K8T/AXTDwLB0yzhFb2CHavBtL68YRuBN3le6HB54Rz6MPGoNx7N2e3ws+b9YL2scQY8jI9iA9gN0FbgeEQLzUXwl90kpAmNyDe4SjH5itwbPfNRi7w0Ogl8KiB1QWUDZc0h34sFjDwrIs+w6GCSnNhWbzP9FAvVd8BzCgbChAkd4VnLQZX9VaQd9gM0b9D/UZoTQAAAABJRU5ErkJggg==",
                ticketNumber: "3022",
                ticketLet: "Y",
                lastName: "Matkalainen",
                firstName: "Hannah",
                seatType: "Economy",
                seatNumber: "12A",
                departureDate: "2024-08-17",
                departureTime: "13:07:34",
                arrivalDate: "2024-08-17",
                arrivalTime: "15:30:00",
                arrivalPort: "MYKONOS TEST",
                vesselDescription: "MYKONOS TEST",
              }
            }else if(persona ==="3"){
              payload.vc.credentialSubject ={
                id: decodedHeaderSubjectDID || "", // Replace with the actual subject DID
                identifier: "Felix Fischer",
                ticketQR:
                  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHkAAAB5AQAAAAA+SX7VAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAABlUlEQVRIDe2YMUtCQRCFZxQVhQo2hdwV2NhZ+ggLFzcBrcNLYktjb2AiBBkDEtFiFE3d7WVo+BR+BX+gtEop3Rjb7ndmxmh8HTIz5TdvzZk5MhGoUZ1Hnz1swr3/ehyHt6nuKPexG5XQPeDqcgrBXT3wGso+ULuLoDr/owxPI27WqZLPKpFvH2FqESkBu8WqwCrCL3r6Ne3Slo6I0A9H/UUXH5KoJwUbPFLU5CJqsZubAiZwVLja4YpAyyKcijulVDrwjeMaLs5CmlgHds1GZc9K8T/AXTDwLB0yzhFb2CHavBtL68YRuBN3le6HB54Rz6MPGoNx7N2e3ws+b9YL2scQY8jI9iA9gN0FbgeEQLzUXwl90kpAmNyDe4SjH5itwbPfNRi7w0Ogl8KiB1QWUDZc0h34sFjDwrIs+w6GCSnNhWbzP9FAvVd8BzCgbChAkd4VnLQZX9VaQd9gM0b9D/UZoTQAAAABJRU5ErkJggg==",
                ticketNumber: "3022",
                ticketLet: "Y",
                lastName: "Fischer",
                firstName: "Felix",
                seatType: "Economy",
                seatNumber: "12A",
                departureDate: "2024-08-17",
                departureTime: "13:07:34",
                arrivalDate: "2024-08-17",
                arrivalTime: "15:30:00",
                arrivalPort: "MYKONOS TEST",
                vesselDescription: "MYKONOS TEST",
              }
            } 
          } else {
            //sign as jwt
            payload = {
              iss: serverURL,
              sub: decodedHeaderSubjectDID || "",
              exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
              iat: Math.floor(Date.now() / 1000), // Token issued at time
              // nbf: Math.floor(Date.now() / 1000),
              jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
              vc: {
                credentialSubject: {
                  id: null,
                  given_name: "John",
                  last_name: "Doe",
                },
                expirationDate: new Date(
                  (Math.floor(Date.now() / 1000) + 60 * 60) * 1000
                ).toISOString(),
                id: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
                issuanceDate: new Date(
                  Math.floor(Date.now() / 1000) * 1000
                ).toISOString(),
                issued: new Date(
                  Math.floor(Date.now() / 1000) * 1000
                ).toISOString(),
                issuer: serverURL,
                type: ["VerifiablePortableDocumentA2"],
                validFrom: new Date(
                  Math.floor(Date.now() / 1000) * 1000
                ).toISOString(),
              },
              // Optional claims
            };
          }
        }
      }
    }

    const signOptions = {
      algorithm: "ES256", // Specify the signing algorithm
    };

    // Define additional JWT header fields
    const additionalHeaders = {
      kid: "aegean#authentication-key",
      typ: "JWT",
    };
    // Sign the token
    const idtoken = jwt.sign(payload, privateKey, {
      ...signOptions,
      header: additionalHeaders, // Include additional headers separately
    });

    // console.log(idtoken);

    /* jwt format */
    res.json({
      format: "jwt_vc_json",
      credential: idtoken,
      c_nonce: generateNonce(),
      c_nonce_expires_in: 86400,
    });
  } else {
    // console.log("Token:", token);
    // console.log("Request Body:", requestBody);
    const { signer, verifier } = await createSignerVerifier(
      pemToJWK(privateKey, "private"),
      pemToJWK(publicKeyPem, "public")
    );
    const sdjwt = new SDJwtVcInstance({
      signer,
      verifier,
      signAlg: "ES256",
      hasher: digest,
      hashAlg: "SHA-256",
      saltGenerator: generateSalt,
    });
    const claims = {
      given_name: "John",
      last_name: "Doe",
    };
    const disclosureFrame = {
      _sd: ["given_name", "last_name"],
    };
    const credential = await sdjwt.issue(
      {
        iss: serverURL,
        iat: new Date().getTime(),
        vct: "VerifiablePortableDocumentA1",
        ...claims,
      },
      disclosureFrame
    );
    res.json({
      format: "vc+sd-jwt",
      credential: credential,
      c_nonce: generateNonce(),
      c_nonce_expires_in: 86400,
    });
  }
});
//issuerConfig.credential_endpoint = serverURL + "/credential";

//ITB
router.get(["/issueStatus"], (req, res) => {
  let sessionId = req.query.sessionId;

  // walletCodeSessions,codeFlowRequestsResults,codeFlowRequests
  const preSessions = getPreCodeSessions();
  const codeSessions = getAuthCodeSessions();
  let result =
    checkIfExistsIssuanceStatus(
      sessionId,
      preSessions.sessions,
      preSessions.results
    ) ||
    checkIfExistsIssuanceStatus(
      sessionId,
      codeSessions.sessions,
      codeSessions.results,
      codeSessions.walletSessions,
      codeSessions.requests
    );
  if (result) {
    console.log("wi9ll send result");
    console.log({
      status: result,
      reason: "ok",
      sessionId: sessionId,
    });
    res.json({
      status: result,
      reason: "ok",
      sessionId: sessionId,
    });
  } else {
    res.json({
      status: "failed",
      reason: "not found",
      sessionId: sessionId,
    });
  }
});

function checkIfExistsIssuanceStatus(
  sessionId,
  sessions,
  sessionResults,
  walletCodeSessions = null,
  codeFlowRequests = null
) {
  let index = sessions.indexOf(sessionId);
  console.log("index is");
  console.log(index);
  // if (index < 0) {
  //   sessions.forEach((value, _index) => {
  //     console.log("checking value to " + value.replace(/-persona=\s+$/, "") +"-checking vs" + sessionId)
  //     if (value.replace(/-persona=.*$/, "") === sessionId) {
  //       console.log("updated index")
  //       index = _index;
  //     }
  //   });
  // }
  if (index >= 0) {
    let status = sessionResults[index].status;
    console.log(`sending status ${status} for session ${sessionId}`);
    console.log(`new sessions`);
    console.log(sessions);
    console.log("new session statuses");
    console.log(sessionResults);
    if (status === "success") {
      sessions.splice(index, 1);
      sessionResults.splice(index, 1);
      if (walletCodeSessions) walletCodeSessions.splice(index, 1);
      if (codeFlowRequests) codeFlowRequests.splice(index, 1);
    }
    return status;
  }
  return null;
}

function getPersonaFromAccessToken(accessToken, personas, accessTokens) {
  let persona = null;
  for (let i = 0; i < accessTokens.length; i++) {
    if (accessTokens[i] === accessToken) {
      persona = personas[i];
    }
  }
  return persona;
}

async function validatePKCE(sessions, code, code_verifier, issuanceResults) {
  for (let i = 0; i < sessions.length; i++) {
    let element = sessions[i];
    if (code === element.sessionId) {
      let challenge = element.challenge;
      let tester = await base64UrlEncodeSha256(code_verifier);
      if (tester === challenge) {
        issuanceResults[i].status = "success";
        console.log("code flow status:" + issuanceResults[i].status);
      }
    }
  }
}

export default router;
