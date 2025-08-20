import { getCredentialSubjectForPersona } from "./personasUtils.js";
import { v4 as uuidv4 } from "uuid";
import fs from "fs";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";

const face_data = fs.readFileSync("./data/face.data", "utf8");
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

  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = nowSec + 60 * 60 * 24 * 30;

  return {
    iss: serverURL,
    sub: decodedHeaderSubjectDID || "",
    iat: nowSec,
    nbf: nowSec,
    exp: expSec,
    jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://europa.eu/2018/credentials/eudi/pid/v1",
    ],
    type: ["VerifiableCredential", "PID"],
    credentialSubject: credentialSubject,
  };
};

export const createEPassportPayload = (serverURL, decodedHeaderSubjectDID) => {
  const nowSec = Math.floor(Date.now() / 1000);
  return {
    iss: serverURL,
    sub: decodedHeaderSubjectDID || uuidv4(),
    iat: nowSec,
    nbf: nowSec,
    exp: nowSec + 60 * 60, // 1 hour
    jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://schemas.prod.digitalcredentials.iata.org/contexts/iata_credential.jsonld",
    ],
    type: ["VerifiableCredential", "ePassportCredential"],
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
              digestHashAlgorithmIdentifier: "sha-256",
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
              digestHashAlgorithmIdentifier: "sha-256",
              versionNumber: 1,
            },
          },
        },
      },
    },
  };
};

export const createStudentIDPayload = (
  token,
  serverURL,
  decodedHeaderSubjectDID
) => {
  const preSessions = getPreCodeSessions();
  const persona = getPersonaFromAccessToken(
    token,
    preSessions.personas,
    preSessions.accessTokens
  );

  let credentialSubject = {
    id: decodedHeaderSubjectDID || uuidv4(),
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
      mail: "mario.conti@ewc.eu",
    };
  } else if (persona === "2") {
    credentialSubject = {
      ...credentialSubject,
      identifier: "hannah@ewc.eu",
      familyName: "Matkalainen",
      firstName: "Hannah",
      displayName: "Hannah Matkalainen",
      commonName: "Hannah Matkalainen",
      mail: "hannah@ewc.eu",
    };
  } else if (persona === "3") {
    credentialSubject = {
      ...credentialSubject,
      identifier: "felix@ewc.eu",
      familyName: "Fischer",
      firstName: "Felix",
      displayName: "Felix Fischer",
      commonName: "Felix Fischer",
      mail: "felix@ewc.eu",
    };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = nowSec + 60 * 60 * 24 * 30;
  return {
    iss: serverURL,
    sub: decodedHeaderSubjectDID || "",
    iat: nowSec,
    nbf: nowSec,
    exp: expSec,
    jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "StudentID"],
    credentialSubject: credentialSubject,
  };
};

export const createAllianceIDPayload = (serverURL) => {
  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = nowSec + 60 * 60 * 24 * 30;
  return {
    iss: serverURL,
    sub: uuidv4(),
    iat: nowSec,
    nbf: nowSec,
    exp: expSec,
    jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "allianceIDCredential"],
    credentialSubject: {
      id: uuidv4(),
      identifier: {
        schemeID: "European Student Identifier",
        value:
          "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
        id: "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
      },
    },
  };
};

export const createFerryBoardingPassPayload = (
  token,
  serverURL,
  decodedHeaderSubjectDID
) => {
  const preSessions = getPreCodeSessions();
  const persona = getPersonaFromAccessToken(
    token,
    preSessions.personas,
    preSessions.accessTokens
  );

  let credentialSubject = {
    id: decodedHeaderSubjectDID || uuidv4(),
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
    vesselDescription: "Ferry XYZ",
  };

  if (persona === "1") {
    credentialSubject = {
      ...credentialSubject,
      identifier: "Mario Conti",
      lastName: "Conti",
      firstName: "Mario",
      ticketNumber: "3022",
      arrivalPort: "Mykonos",
      vesselDescription: "Ferry to Mykonos",
    };
  } else if (persona === "2") {
    credentialSubject = {
      ...credentialSubject,
      identifier: "Hannah Matkalainen",
      lastName: "Matkalainen",
      firstName: "Hannah",
      ticketNumber: "3022",
      arrivalPort: "Santorini",
      vesselDescription: "Ferry to Santorini",
    };
  } else if (persona === "3") {
    credentialSubject = {
      ...credentialSubject,
      identifier: "Felix Fischer",
      lastName: "Fischer",
      firstName: "Felix",
      ticketNumber: "3022",
      arrivalPort: "Crete",
      vesselDescription: "Ferry to Crete",
    };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = nowSec + 60 * 60 * 24 * 30;
  return {
    iss: serverURL,
    sub: decodedHeaderSubjectDID || "",
    iat: nowSec,
    nbf: nowSec,
    exp: expSec,
    jti: "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "ferryBoardingPassCredential"],
    credentialSubject: credentialSubject,
  };
};

// SD-JWT HELPERS

export const getPIDSDJWTData = (decodedHeaderSubjectDID) => {
  const currentTimestamp = new Date().getTime();
  const currentDate = new Date();
  const expTimestamp = currentDate.setFullYear(currentDate.getFullYear() + 1);
  const claims = {
    // id: decodedHeaderSubjectDID || uuidv4(),
    given_name: "Hanna",
    family_name: "Matkalainen",
    birth_date: "01.07.2005",
    age_over_18: true,
    issuance_date: currentTimestamp,
    expiry_date: expTimestamp, //expTimestamp.getTime(),
    issuing_authority: "UAegean Test Issuer",
    issuing_country: "Finland",
  };

  const disclosureFrame = {
    _sd: [
      // "id",
      "given_name",
      "family_name",
      "birth_date",
      "age_over_18",
      "expiry_date",
      "issuance_date",
      "issuing_authority",
      "issuing_country",
    ],
  };

  return { claims, disclosureFrame };
};

export const getStudentIDSDJWTData = (credentialPayload, decodedHeaderSubjectDID) => {
  const claims = {
    id: decodedHeaderSubjectDID || uuidv4(),
    identifier: "hanna@aegean.gr",
    schacPersonalUniqueCode: [
      "urn:schac:personalUniqueCode:int:esi:university.edu:12345",
    ],
    schacPersonalUniqueID: "urn:schac:personalUniqueID:us:12345",
    schacHomeOrganization: "university.edu",
    familyName: "Matkalainen",
    firstName: "Hanna",
    displayName: "Hanna Matkalainen",
    dateOfBirth: "01.07.2005",
    commonName: "Hanna Matkalainen",
    mail: "hanna@aegean.gr",
    eduPersonPrincipalName: "hanna@aegean.gr",
    eduPersonPrimaryAffiliation: "student",
    eduPersonAffiliation: ["member", "student"],
    eduPersonScopedAffiliation: ["student@university.edu"],
    eduPersonAssurance: [
      "https://wiki.refeds.org/display/ASS/REFEDS+Assurance+Framework+ver+1.0",
    ],
  };

  if (credentialPayload) {
    claims.firstName = credentialPayload.given_name || claims.firstName;
    claims.familyName = credentialPayload.family_name || claims.familyName;
    claims.mail = credentialPayload.email || claims.mail;
    claims.identifier = credentialPayload.email || claims.identifier;
    claims.eduPersonPrincipalName =
      credentialPayload.eduPersonPrincipalName ||
      credentialPayload.email ||
      claims.eduPersonPrincipalName;
    claims.schacHomeOrganization =
      credentialPayload.schacHomeOrganization || claims.schacHomeOrganization;
    claims.schacPersonalUniqueID =
      credentialPayload.eduPersonUniqueId ||
      credentialPayload.email ||
      claims.schacPersonalUniqueID;

    const cn =
      credentialPayload.cn ||
      (credentialPayload.given_name && credentialPayload.family_name
        ? `${credentialPayload.given_name} ${credentialPayload.family_name}`
        : null);

    if (cn) {
      claims.displayName = cn;
      claims.commonName = cn;
    }
  }

  const disclosureFrame = {
    _sd: [
      "id",
      "identifier",
      "schacPersonalUniqueCode",
      "schacPersonalUniqueID",
      "schacHomeOrganization",
      "familyName",
      "firstName",
      "displayName",
      "dateOfBirth",
      "commonName",
      "mail",
      "eduPersonPrincipalName",
      "eduPersonPrimaryAffiliation",
      "eduPersonAffiliation",
      "eduPersonScopedAffiliation",
      "eduPersonAssurance",
    ],
  };

  return { claims, disclosureFrame };
};

export const getAllianceIDSDJWTData = (decodedHeaderSubjectDID) => {
  const claims = {
    id: decodedHeaderSubjectDID || uuidv4(),
    identifier: {
      schemeID: "European Student Identifier",
      value:
        "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
      id: "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
    },
  };

  const disclosureFrame = {
    _sd: ["id", "identifier.schemeID", "identifier.value", "identifier.id"],
  };

  return { claims, disclosureFrame };
};

export const getFerryBoardingPassSDJWTData = async (
  decodedHeaderSubjectDID
) => {
  let txtToEncode = encodeURIComponent("Y;6759");
  let code = qr.image(txtToEncode, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "jpeg";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  //data:image/jpeg;base64,

  const claims = {
    id: decodedHeaderSubjectDID || uuidv4(),
    identifier: "John Doe",
    ticketQR: encodedQR,
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
  };

  const disclosureFrame = {
    _sd: [
      "id",
      "identifier",
      "ticketQR",
      "ticketNumber",
      "ticketLet",
      "lastName",
      "firstName",
      "seatType",
      "seatNumber",
      "departureDate",
      "departureTime",
      "arrivalDate",
      "arrivalTime",
      "arrivalPort",
      "vesselDescription",
    ],
  };

  return { claims, disclosureFrame };
};

export const getGenericSDJWTData = (decodedHeaderSubjectDID, credType) => {
  const claims = {
    // id: decodedHeaderSubjectDID || uuidv4(),
    given_name: "John",
    last_name: "Doe",
  };

  const disclosureFrame = {
    _sd: ["given_name", "last_name"],
  };

  return { claims, disclosureFrame };
};

export const getEPassportSDJWTData = (decodedHeaderSubjectDID) => {
  const claims = {
    id: decodedHeaderSubjectDID || uuidv4(),
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
    },
  };

  const disclosureFrame = {
    _sd: [
      "id",
      "electronicPassport.dataGroup1.birthdate",
      "electronicPassport.dataGroup1.docTypeCode",
      "electronicPassport.dataGroup1.expiryDate",
      "electronicPassport.dataGroup1.genderCode",
      "electronicPassport.dataGroup1.holdersName",
      "electronicPassport.dataGroup1.issuerCode",
      "electronicPassport.dataGroup1.natlText",
      "electronicPassport.dataGroup1.passportNumberIdentifier",
    ],
  };

  return { claims, disclosureFrame };
};

export const getVReceiptSDJWTData = (decodedHeaderSubjectDID) => {
  const claims = {
    id: decodedHeaderSubjectDID || uuidv4(),

    // Monetary Total
    "monetary_total.line_extension_amount": 150.75,
    "monetary_total.tax_inclusive_amount": 180.9,
    "monetary_total.payable_amount": 180.9,

    // Tax Total
    "tax_total.tax_subtotal.tax_amount": 30.15,
    "tax_total.tax_subtotal.tax_category.tax_scheme.name": "Standard VAT",
    "tax_total.tax_subtotal.percent": 20,
    "tax_total.tax_amount": 30.15,

    // Address
    "address.street_name": "123 Main Street",
    "address.city_name": "Sample City",
    "address.postcode": "SC12345",
    "address.country_identifier": "GB",

    // Payment Means
    "payment_means.payment_means_code": "PM01",
    "payment_means.card_account.network_id": "VISA",
    "payment_means.card_account.account_number_id": "411111******1111",

    // Item Property
    "item_property.item_property_name": "Color",
    "item_property.value": "Red",

    // Purchase Receipt
    "purchase_receipt.id": "PR123456789",
    "purchase_receipt.issue_date": "2024-04-27",
    "purchase_receipt.document_currency_code": "GBP",
    "purchase_receipt.legal_monetary_total": 180.9,
    "purchase_receipt.seller_supplier_party.supplier_party_id": "SPID123456",
    "purchase_receipt.tax_included_indicator": true,
    "purchase_receipt.payment.paid_amount": 180.9,
    "purchase_receipt.payment.authorization_id": "AUTH123456789",
    "purchase_receipt.payment.transaction_id": "TXN123456789",
    "purchase_receipt.purchase_receipt_line.id": "PRL123456789",
    "purchase_receipt.purchase_receipt_line.quantity": 2,
    "purchase_receipt.purchase_receipt_line.tax_inclusive_line_extension_amount": 80.45,
    "purchase_receipt.purchase_receipt_line.item.commodity_classification.item_classification_code": "ICC67890",

    // Delivery
    "delivery.actual_delivery_date": "2024-04-28",
    "delivery.actual_delivery_time": "14:30",

    // Party Name
    "party_name.name": "Sample Seller Ltd.",

    // Party Identification
    "party_identification.id": "PID123456789",
  };

  const disclosureFrame = {
    _sd: [
      "id",

      // Monetary Total
      "monetary_total.line_extension_amount",
      "monetary_total.tax_inclusive_amount",
      "monetary_total.payable_amount",

      // Tax Total
      "tax_total.tax_subtotal.tax_amount",
      "tax_total.tax_subtotal.tax_category.tax_scheme.name",
      "tax_total.tax_subtotal.percent",
      "tax_total.tax_amount",

      // Address
      "address.street_name",
      "address.city_name",
      "address.postcode",
      "address.country_identifier",

      // Payment Means
      "payment_means.payment_means_code",
      "payment_means.card_account.network_id",
      "payment_means.card_account.account_number_id",

      // Item Property
      "item_property.item_property_name",
      "item_property.value",

      // Purchase Receipt
      "purchase_receipt.id",
      "purchase_receipt.issue_date",
      "purchase_receipt.document_currency_code",
      "purchase_receipt.legal_monetary_total",
      "purchase_receipt.seller_supplier_party.supplier_party_id",
      "purchase_receipt.tax_included_indicator",
      "purchase_receipt.payment.paid_amount",
      "purchase_receipt.payment.authorization_id",
      "purchase_receipt.payment.transaction_id",
      "purchase_receipt.purchase_receipt_line.id",
      "purchase_receipt.purchase_receipt_line.quantity",
      "purchase_receipt.purchase_receipt_line.tax_inclusive_line_extension_amount",
      "purchase_receipt.purchase_receipt_line.item.commodity_classification.item_classification_code",

      // Delivery
      "delivery.actual_delivery_date",
      "delivery.actual_delivery_time",

      // Party Name
      "party_name.name",

      // Party Identification
      "party_identification.id",
    ],
  };

  return { claims, disclosureFrame };
};

export const getVReceiptSDJWTDataWithPayload = (
  payload,
  decodedHeaderSubjectDID
) => {

  console.log("payload", payload);
  const claims = {
    id: decodedHeaderSubjectDID || uuidv4(), // Top-level ID (not nested under purchase_receipt)
    ...payload, // Spread payload, assuming it matches metadata naming
  };

  const disclosureFrame = {
    _sd: [
      "id", // Top-level ID

      // Monetary Total
      "monetary_total.line_extension_amount",
      "monetary_total.tax_inclusive_amount",
      "monetary_total.payable_amount",

      // Tax Total
      "tax_total.tax_subtotal.tax_amount",
      "tax_total.tax_subtotal.tax_category.tax_scheme.name",
      "tax_total.tax_subtotal.percent",
      "tax_total.tax_amount",

      // Address
      "address.street_name",
      "address.city_name",
      "address.postcode",
      "address.country_identifier",

      // Payment Means
      "payment_means.payment_means_code",
      "payment_means.card_account.network_id",
      "payment_means.card_account.account_number_id",

      // Item Property
      "item_property.item_property_name",
      "item_property.value",

      // Purchase Receipt
      "purchase_receipt.id",
      "purchase_receipt.issue_date",
      "purchase_receipt.document_currency_code",
      "purchase_receipt.legal_monetary_total",
      "purchase_receipt.seller_supplier_party.supplier_party_id",
      "purchase_receipt.tax_included_indicator",
      "purchase_receipt.payment.paid_amount",
      "purchase_receipt.payment.authorization_id",
      "purchase_receipt.payment.transaction_id",
      "purchase_receipt.purchase_receipt_line.id",
      "purchase_receipt.purchase_receipt_line.quantity",
      "purchase_receipt.purchase_receipt_line.tax_inclusive_line_extension_amount",
      "purchase_receipt.purchase_receipt_line.item.commodity_classification.item_classification_code",

      // Delivery
      "delivery.actual_delivery_date",
      "delivery.actual_delivery_time",

      // Party Name
      "party_name.name",

      // Party Identification
      "party_identification.id",
    ],
  };

  return { claims, disclosureFrame };
};

export const createPaymentWalletAttestationPayload = (serverURL) => {
  const currentTime = Math.floor(Date.now() / 1000);
  const expirationTime = currentTime + 60 * 60 * 24 * 30; // Token expiration (30 days)

  // Credential Subject data for claims
  const credentialSubject = {
    id: "PSP-account-identifier", // Replace with actual account identifier
    fundingSource: {
      type: "card", // Example funding source type
      parLastFour: "0010",
      panLastFour: "0010", // Example PAN ends in 000000
      iin: "401636", // Example IIN
      aliasId: "alias-12345", // Example alias ID
      scheme: "Visa", // Example card scheme
      currency:"EUR",
      icon: "https://cdn4.iconfinder.com/data/icons/flat-brand-logo-2/512/visa-512.png", // Example card icon URL
    },
    // accounts: ["123"], //
    // account_holder_id: "luke skywalker", //
  };
  // Claims for the payload
  const claims = {
    aud: `${serverURL}/.well-known/oauth-authorization-server`,
    sub: "PSP-account-identifier", // Ensure consistency with 'id' in credentialSubject
    // scope: "PaymentWalletAttestation",
    ...credentialSubject,
  };
  // Disclosure frame for selective disclosure
  const disclosureFrame = {
    _sd: [
      "id", // Account ID
      // "credentialSubject.fundingSource.type", // Funding Source Type
      // "credentialSubject.fundingSource.panEndsIn", // PAN Ends In
      // "credentialSubject.fundingSource.iin", // IIN
      // "credentialSubject.fundingSource.aliasId", // Alias ID
      // "credentialSubject.fundingSource.scheme", // Card Scheme
      // "credentialSubject.fundingSource.icon", // Card Icon URL
      "parLastFour",
      "panLastFour",
      "iin",
      "aliasId",
      "scheme",
      "icon",
      "currency",
      "accounts", // Account Identifier
      "account_holder_id", // Account Holder ID
    ],
  };

  return { claims, disclosureFrame };
};

export const createPhotoIDAttestationPayload = (serverURL) => {
  // Generate basic timestamps for demonstration
  const currentTime = Math.floor(Date.now() / 1000);
  const expirationTime = currentTime + 60 * 60 * 24 * 30; // 30 days

  // Example ID for the credential subject (like a DID or unique ID)
  const subjectId = uuidv4();

  // Mock claims — this is where you embed your PhotoID schema data.
  // The top-level "id" is analogous to your receipt's approach.
  const claims = {
    id: subjectId,

    // Typically you'd include standard JWT/VC fields too
    iss: serverURL,
    iat: currentTime,
    exp: expirationTime,
    vct: "eu.europa.ec.eudi.photoid.1",

    iso23220: {
      family_name_unicode: "Matkalainen",
      given_name_unicode: "Hanna",
      birth_date: "2005-01-02",
      portrait: face_data,
      issue_date: "2023-01-01",
      expiry_date: "2027-01-01",
      issuing_authority_unicode: "Finland Test Authority",
      issuing_country: "FIN",
      sex: "2", // 0=unknown,1=male,2=female,9=not-applicable
      nationality: "FIN",
      document_number: "ABC1234567",
      name_at_birth: "Hanna Matkalainen",
      birthplace: "Roveaniemi",
      portrait_capture_date: "2023-02-01T10:00:00Z",
      resident_address_unicode: "123 Elm Street",
      resident_city_unicode: "Roveaniemi",
      resident_postal_code: "W12345",
      resident_country: "FI",
      age_over_18: true,
      age_in_years: 33,
      age_birth_year: 1990,
      family_name_latin1: "Matkalainen",
      given_name_latin1: "Hanna",
    },

    photoid: {
      person_id: "PERSON-98765",
      birth_country: "FI",
      birth_state: "Roveaniemi",
      birth_city: "Roveaniemi",
      administrative_number: "ADMIN-123",
      resident_street: "123 Elm Street",
      resident_house_number: "12",
      travel_document_number: "XP8271602",
      resident_state: "Roveaniemi",
    },

    dtc: {
      dtc_version: "1.0.0",
      dtc_dg1: "Full-MRZ-data-placeholder",
      dtc_dg2: face_data,
      dtc_sod: face_data,
      // Example placeholders for optional data groups
      dtc_dg3: "base64-binary-dg3",
      dtc_dg4: "base64-binary-dg4",
      dtc_dg16: "base64-binary-dg16",
      dg_content_info: "base64-dtcContentInfo",
    },
  };

  const disclosureFrame = {
    _sd: [
      // ISO23220 Information - Only disclosable fields
      "iso23220.family_name_unicode",
      "iso23220.given_name_unicode",
      "iso23220.birth_date",
      "iso23220.portrait",
      "iso23220.issue_date",
      "iso23220.expiry_date",
      "iso23220.issuing_authority_unicode",
      "iso23220.issuing_country",
      "iso23220.sex",
      "iso23220.nationality",
      "iso23220.document_number",
      "iso23220.name_at_birth",
      "iso23220.birthplace",
      "iso23220.portrait_capture_date",
      "iso23220.resident_address_unicode",
      "iso23220.resident_city_unicode",
      "iso23220.resident_postal_code",
      "iso23220.resident_country",
      "iso23220.age_over_18",
      "iso23220.age_in_years",
      "iso23220.age_birth_year",
      "iso23220.family_name_latin1",
      "iso23220.given_name_latin1",

      // PhotoID Information
      "photoid.person_id",
      "photoid.birth_country",
      "photoid.birth_state",
      "photoid.birth_city",
      "photoid.administrative_number",
      "photoid.resident_street",
      "photoid.resident_house_number",
      "photoid.travel_document_number",
      "photoid.resident_state",

      // DTC Information
      "dtc.dtc_version",
      "dtc.dtc_dg1",
      "dtc.dtc_dg2",
      "dtc.dtc_sod",
      "dtc.dtc_dg3",
      "dtc.dtc_dg4",
      "dtc.dtc_dg16",
      "dtc.dg_content_info"
    ]
  };

  return { claims, disclosureFrame };
};

export const createPCDAttestationPayload = (serverURL) => {
  // Generate basic timestamps for demonstration
  const currentTime = Math.floor(Date.now() / 1000);
  const expirationTime = currentTime + 60 * 60 * 24 * 30; // 30 days

  // Example ID for the credential subject (like a DID or unique ID)
  const subjectId = uuidv4();

  // Mock claims — this is where you embed your PhotoID schema data.
  // The top-level "id" is analogous to your receipt's approach.
  const claims = {
    id: subjectId,
    // Typically you'd include standard JWT/VC fields too
    iss: serverURL,
    iat: currentTime,
    exp: expirationTime,
    vct: "eu.europa.ec.eudi.pcd.1",

    surname: "Matkalainen",
    given_name: "Hanna",
    phone: "+358 457 123 4567",
    email_address: "hanna@suomil.com",
    city_address: "Rovaniemi",
    street_address: "Tähtikuja 1",
    country_address: "Finland",
  };

  const disclosureFrame = {
    _sd: [
      "surname",
      "given_name",
      "phone",
      "email_address",
      "city_address",
      "country_address",
      "street_address",
    ],
  };

  return { claims, disclosureFrame };
};

export const createCombinedCredentialsPayload = (
  token,
  serverURL,
  decodedHeaderSubjectDID
) => {
  const photoID = createPhotoIDAttestationPayload();
  const studentID = getStudentIDSDJWTData(decodedHeaderSubjectDID);
  const pid = createPIDPayload(token, serverURL, decodedHeaderSubjectDID);

  return [photoID, studentID, pid]; // Add other credentials as needed
};


export const getLoyaltyCardSDJWTDataWithPayload = (
  payload,
  decodedHeaderSubjectDID
) => {
  console.log("payload", payload);

  const validPayload = {
    customer: {
      first_name: payload["customer.first_name"],
      last_name: payload["customer.last_name"],
      nationality: payload["customer.nationality"],
      address: payload["customer.address"],
      city: payload["customer.city"],
      zip_code: payload["customer.zip_code"],
      phone: payload["customer.phone"],
      mobile: payload["customer.mobile"],
      birth_date: payload["customer.birth_date"],
      email: payload["customer.email"],
    },
    loyalty_card: {
      id: payload["loyalty_card.id"],
      issue_date: payload["loyalty_card.issue_date"],
      status: payload["loyalty_card.status"],
      type: payload["loyalty_card.type"],
    },
    portfolio: {
      available_points: payload["portfolio.available_points"],
      available_miles: payload["portfolio.available_miles"],
      available_wallet: payload["portfolio.available_wallet"],
      last_updated: payload["portfolio.last_updated"],
    },
    organization: {
      name: payload["organization.name"],
      id: payload["organization.id"],
      country: payload["organization.country"],
    },
    credential: {
      type: payload["credential.type"],
      issuer: payload["credential.issuer"],
      issuance_date: payload["credential.issuance_date"],
      expiry_date: payload["credential.expiry_date"],
    },
  };
  
  

  console.log("validPayload", validPayload);

  const claims = {
    id: decodedHeaderSubjectDID || uuidv4(), // Top-level ID
    ...validPayload,
  };
  const disclosureFrame = {
    _sd: [
      "id",

      // Customer Information
      "customer.first_name",
      "customer.last_name",
      "customer.nationality",
      "customer.address",
      "customer.city",
      "customer.zip_code",
      "customer.phone",
      "customer.mobile",
      "customer.birth_date",
      "customer.email",

      // Loyalty Card Information
      "loyalty_card.id",
      "loyalty_card.issue_date",
      "loyalty_card.status",
      "loyalty_card.type",

      // Portfolio Information
      "portfolio.available_points",
      "portfolio.available_miles",
      "portfolio.available_wallet",
      "portfolio.last_updated",

      // Organization Information
      "organization.name",
      "organization.id",
      "organization.country",

      // Credential Metadata
      "credential.type",
      "credential.issuer",
      "credential.issuance_date",
      "credential.expiry_date",
    ],
  };

  return { claims, disclosureFrame };
};
