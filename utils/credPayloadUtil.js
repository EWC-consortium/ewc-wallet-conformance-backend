// Helper functions to create payloads for different credential types
export const createPIDPayload = (token, serverURL, decodedHeaderSubjectDID) => {
  const preSessions = getPreCodeSessions();
  const persona = getPersonaFromAccessToken(
    token,
    preSessions.personas,
    preSessions.accessTokens
  );
  const credentialSubject = getCredentialSubjectForPersona(
    persona,
    decodedHeaderSubjectDID
  );

  return {
    iss: serverURL,
    sub: decodedHeaderSubjectDID || "",
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30, // Token expiration time (30 days)
    iat: Math.floor(Date.now() / 1000),
    jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
    vc: {
      credentialSubject: credentialSubject,
      expirationDate: new Date(
        (Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30) * 1000
      ).toISOString(),
      id: decodedHeaderSubjectDID,
      issuanceDate: new Date(
        Math.floor(Date.now() / 1000) * 1000
      ).toISOString(),
      issuer: serverURL,
      type: ["PID"],
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://europa.eu/2018/credentials/eudi/pid/v1",
      ],
      validFrom: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
    },
  };
};

export const createEPassportPayload = (serverURL, decodedHeaderSubjectDID) => {
  return {
    iss: serverURL,
    sub: decodedHeaderSubjectDID || "",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour)
    jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
    vc: {
      credentialSubject: {
        id: decodedHeaderSubjectDID || "",
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
                  { dataGroupNumber: 1, valueBinaryObject: "someHashUri" },
                ],
                digestHashAlgorithmIdentifier: "SHA-256",
                versionNumber: 1,
              },
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
      validFrom: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
    },
  };
};


export const createStudentIDPayload = (token, serverURL, decodedHeaderSubjectDID) => {
    const preSessions = getPreCodeSessions();
    const persona = getPersonaFromAccessToken(token, preSessions.personas, preSessions.accessTokens);
  
    let credentialSubject = {
      id: decodedHeaderSubjectDID || "",
      identifier: "john.doe@university.edu",
      schacPersonalUniqueCode: ["urn:schac:personalUniqueCode:int:esi:university.edu:12345"],
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
      eduPersonAssurance: ["https://wiki.refeds.org/display/ASS/REFEDS+Assurance+Framework+ver+1.0"]
    };
  
    // Handle different persona data if available
    if (persona === "1") {
      credentialSubject = {
        ...credentialSubject,
        identifier: "mario.conti@ewc.eu",
        familyName: "Conti",
        firstName: "Mario",
        displayName: "Mario Conti",
        commonName: "Mario Conti",
        mail: "mario.conti@ewc.eu"
      };
    } else if (persona === "2") {
      credentialSubject = {
        ...credentialSubject,
        identifier: "hannah@ewc.eu",
        familyName: "Matkalainen",
        firstName: "Hannah",
        displayName: "Hannah Matkalainen",
        commonName: "Hannah Matkalainen",
        mail: "hannah@ewc.eu"
      };
    } else if (persona === "3") {
      credentialSubject = {
        ...credentialSubject,
        identifier: "felix@ewc.eu",
        familyName: "Fischer",
        firstName: "Felix",
        displayName: "Felix Fischer",
        commonName: "Felix Fischer",
        mail: "felix@ewc.eu"
      };
    }
  
    return {
      iss: serverURL,
      sub: decodedHeaderSubjectDID || "",
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30,
      iat: Math.floor(Date.now() / 1000),
      jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
      vc: {
        type: ["StudentID"],
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        issuer: serverURL,
        credentialSubject: credentialSubject,
        issuanceDate: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
        expirationDate: new Date((Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30) * 1000).toISOString(),
        validFrom: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString()
      }
    };
};


export const createAllianceIDPayload = (serverURL, decodedHeaderSubjectDID) => {
    return {
      iss: serverURL,
      sub: decodedHeaderSubjectDID || "",
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30,
      iat: Math.floor(Date.now() / 1000),
      jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
      vc: {
        type: ["allianceIDCredential"],
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        issuer: serverURL,
        credentialSubject: {
          id: decodedHeaderSubjectDID || "",
          identifier: {
            schemeID: "European Student Identifier",
            value: "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
            id: "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ"
          }
        },
        issuanceDate: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
        expirationDate: new Date((Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30) * 1000).toISOString(),
        validFrom: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString()
      }
    };
  };

 export const createFerryBoardingPassPayload = (token, serverURL, decodedHeaderSubjectDID) => {
    const preSessions = getPreCodeSessions();
    const persona = getPersonaFromAccessToken(token, preSessions.personas, preSessions.accessTokens);
  
    let credentialSubject = {
      id: decodedHeaderSubjectDID || "",
      identifier: "John Doe",
      ticketQR: "data:image/png;base64,someBase64EncodedQR",
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
      vesselDescription: "Ferry XYZ"
    };
  
    if (persona === "1") {
      credentialSubject = {
        ...credentialSubject,
        identifier: "Mario Conti",
        lastName: "Conti",
        firstName: "Mario",
        ticketNumber: "3022",
        arrivalPort: "Mykonos",
        vesselDescription: "Ferry to Mykonos"
      };
    } else if (persona === "2") {
      credentialSubject = {
        ...credentialSubject,
        identifier: "Hannah Matkalainen",
        lastName: "Matkalainen",
        firstName: "Hannah",
        ticketNumber: "3022",
        arrivalPort: "Santorini",
        vesselDescription: "Ferry to Santorini"
      };
    } else if (persona === "3") {
      credentialSubject = {
        ...credentialSubject,
        identifier: "Felix Fischer",
        lastName: "Fischer",
        firstName: "Felix",
        ticketNumber: "3022",
        arrivalPort: "Crete",
        vesselDescription: "Ferry to Crete"
      };
    }
  
    return {
      iss: serverURL,
      sub: decodedHeaderSubjectDID || "",
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30,
      iat: Math.floor(Date.now() / 1000),
      jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
      vc: {
        type: ["VerifiableCredential", "ferryBoardingPassCredential"],
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        issuer: serverURL,
        credentialSubject: credentialSubject,
        issuanceDate: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
        expirationDate: new Date((Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30) * 1000).toISOString(),
        validFrom: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString()
      }
    };
  };
  

// SD-JWT HELPERS

 export const getPIDSDJWTData = (decodedHeaderSubjectDID) => {
    const claims = {
      id: decodedHeaderSubjectDID || "",
      given_name: "John",
      family_name: "Doe",
      birth_date: "1990-01-01",
      age_over_18: true,
    };
  
    const disclosureFrame = {
      _sd: ["id", "given_name", "family_name", "birth_date", "age_over_18"]
    };
  
    return { claims, disclosureFrame };
  };
  

  export const getStudentIDSDJWTData = (decodedHeaderSubjectDID) => {
    const claims = {
      id: decodedHeaderSubjectDID || "",
      identifier: "john.doe@university.edu",
      schacPersonalUniqueCode: ["urn:schac:personalUniqueCode:int:esi:university.edu:12345"],
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
      eduPersonAssurance: ["https://wiki.refeds.org/display/ASS/REFEDS+Assurance+Framework+ver+1.0"]
    };
  
    const disclosureFrame = {
      _sd: [
        "id", "identifier", "schacPersonalUniqueCode", "schacPersonalUniqueID", "schacHomeOrganization",
        "familyName", "firstName", "displayName", "dateOfBirth", "commonName", "mail", "eduPersonPrincipalName",
        "eduPersonPrimaryAffiliation", "eduPersonAffiliation", "eduPersonScopedAffiliation", "eduPersonAssurance"
      ]
    };
  
    return { claims, disclosureFrame };
  };

export const getAllianceIDSDJWTData = (decodedHeaderSubjectDID) => {
    const claims = {
      id: decodedHeaderSubjectDID || "",
      identifier: {
        schemeID: "European Student Identifier",
        value: "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
        id: "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ"
      }
    };
  
    const disclosureFrame = {
      _sd: ["id", "identifier.schemeID", "identifier.value", "identifier.id"]
    };
  
    return { claims, disclosureFrame };
  };
  

  export const getFerryBoardingPassSDJWTData = (decodedHeaderSubjectDID) => {
    const claims = {
      id: decodedHeaderSubjectDID || "",
      identifier: "John Doe",
      ticketQR: "data:image/png;base64,someBase64EncodedQR",
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
      vesselDescription: "Ferry XYZ"
    };
  
    const disclosureFrame = {
      _sd: [
        "id", "identifier", "ticketQR", "ticketNumber", "ticketLet", "lastName", "firstName",
        "seatType", "seatNumber", "departureDate", "departureTime", "arrivalDate", "arrivalTime",
        "arrivalPort", "vesselDescription"
      ]
    };
  
    return { claims, disclosureFrame };
  };
  
  export const getGenericSDJWTData = (decodedHeaderSubjectDID, credType) => {
    const claims = {
      id: decodedHeaderSubjectDID || "",
      given_name: "John",
      last_name: "Doe"
    };
  
    const disclosureFrame = {
      _sd: ["id", "given_name", "last_name"]
    };
  
    return { claims, disclosureFrame };
  };
  

  export const getEPassportSDJWTData = (decodedHeaderSubjectDID) => {
    const claims = {
      id: decodedHeaderSubjectDID || "",
      electronicPassport: {
        dataGroup1: {
          birthdate: "1990-01-01",
          docTypeCode: "P",
          expiryDate: "2030-01-01",
          genderCode: "M",
          holdersName: "John Doe",
          issuerCode: "GR",
          natlText: "Hellenic",
          passportNumberIdentifier: "123456789"
        },
        dataGroup15: {
          activeAuthentication: {
            publicKeyBinaryObject: "somePublicKeyUri"
          }
        },
        dataGroup2EncodedFaceBiometrics: {
          faceBiometricDataEncodedPicture: "someBiometricUri"
        }
      }
    };
  
    const disclosureFrame = {
      _sd: ["id", "electronicPassport.dataGroup1.birthdate", "electronicPassport.dataGroup1.docTypeCode",
        "electronicPassport.dataGroup1.expiryDate", "electronicPassport.dataGroup1.genderCode",
        "electronicPassport.dataGroup1.holdersName", "electronicPassport.dataGroup1.issuerCode",
        "electronicPassport.dataGroup1.natlText", "electronicPassport.dataGroup1.passportNumberIdentifier"]
    };
  
    return { claims, disclosureFrame };
  };
  