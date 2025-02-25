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
    sub: decodedHeaderSubjectDID || uuidv4(),
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
      issuanceDate: new Date(
        Math.floor(Date.now() / 1000) * 1000
      ).toISOString(),
      expirationDate: new Date(
        (Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30) * 1000
      ).toISOString(),
      validFrom: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
    },
  };
};

export const createAllianceIDPayload = (serverURL) => {
  return {
    iss: serverURL,
    sub: decodedHeaderSubjectDID || uuidv4(),
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
          value:
            "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
          id: "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
        },
      },
      issuanceDate: new Date(
        Math.floor(Date.now() / 1000) * 1000
      ).toISOString(),
      expirationDate: new Date(
        (Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30) * 1000
      ).toISOString(),
      validFrom: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
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
      issuanceDate: new Date(
        Math.floor(Date.now() / 1000) * 1000
      ).toISOString(),
      expirationDate: new Date(
        (Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30) * 1000
      ).toISOString(),
      validFrom: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
    },
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

export const getStudentIDSDJWTData = (decodedHeaderSubjectDID) => {
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
    "MonetaryTotal.lineExtensionAmount": 150.75,
    "MonetaryTotal.taxInclusiveAmount": 180.9,
    "MonetaryTotal.payableAmount": 180.9,

    // Tax Total
    "TaxTotal.taxSubtotal_": {
      taxableAmount: 150.75,
      taxSubtotalTaxAmount: 30.15,
      taxCategory_: "VAT",
      percent: 20,
    },
    "TaxTotal.taxAmount": 30.15,

    // Address
    "Address.streetName": "123 Main Street",
    "Address.cityName": "Sample City",
    "Address.postcode": "SC12345",
    "Address.countryIdentifier": "GB",

    // Tax Category
    "TaxCategory.taxScheme_": "VAT Scheme",

    // Item Property
    "ItemProperty.itemPropertyName": "Color",
    "ItemProperty.value": "Red",

    // Tax Scheme
    "TaxScheme.taxSchemeName": "Standard VAT",

    // Allowance Charge
    "AllowanceCharge.amount": 10.0,
    "AllowanceCharge.allowanceChargeReason": "Discount Applied",

    // Party Name
    "PartyName.name": "Sample Seller Ltd.",

    // Payment Means
    "PaymentMeans.cardAccount_": {
      networkID: "VISA",
      accountNumberID: "411111******1111",
    },
    "PaymentMeans.paymentMeansCode": "PM01",

    // Party Identification
    "PartyIdentification.iD": "PID123456789",

    // Purchase Receipt
    "PurchaseReceipt.paymentMeans_": "Credit Card",
    "PurchaseReceipt.note": "Thank you for your purchase!",
    "PurchaseReceipt.delivery_": "Standard Shipping",
    "PurchaseReceipt.taxIncludedIndicator": true,
    "PurchaseReceipt.taxTotal_": 30.15,
    "PurchaseReceipt.accountingCustomerParty_": "Customer Account",
    "PurchaseReceipt.documentCurrencyCode": "GBP",
    "PurchaseReceipt.payment_": "Paid",
    "PurchaseReceipt.sellerSupplierParty": "Sample Seller Ltd.",
    "PurchaseReceipt.legalMonetaryTotal": 180.9,
    "PurchaseReceipt.salesDocumentReference": "SDR123456",
    "PurchaseReceipt.iD": "PR123456789",
    "PurchaseReceipt.issueDate": "2024-04-27",
    "PurchaseReceipt.purchaseReceiptLine-1": "Line1",

    // Tax Subtotal
    "TaxSubtotal.taxableAmount": 150.75,
    "TaxSubtotal.taxSubtotalTaxAmount": 30.15,
    "TaxSubtotal.taxCategory_": "VAT",
    "TaxSubtotal.percent": 20,

    // Item
    "Item.commodityClassification_": "CC123",
    "Item.itemInstance_": "Instance1",
    "Item.additionalItemProperty": "Property1",

    // Payment
    "Payment.authorizationID": "AUTH123456789",
    "Payment.paidAmount": 180.9,
    "Payment.transactionID": "TXN123456789",

    // Supplier Party
    "SupplierParty.party_": "SupplierParty1",
    "SupplierParty.supplierPartyID": "SPID123456",

    // Party
    "Party.partyIdentification_.iD": "PID987654321",
    "Party.partyName_.name": "Sample Buyer Ltd.",
    "Party.postalAddress_.streetName": "456 Another St.",
    "Party.postalAddress_.cityName": "Another City",
    "Party.postalAddress_.postcode": "AC54321",
    "Party.postalAddress_.countryIdentifier": "GB",

    // Commodity Classification
    "CommodityClassification.itemClassificationCode": "ICC12345",

    // Card Account
    "CardAccount.networkID": "MASTERCARD",
    "CardAccount.accountNumberID": "550000******0004",

    // Customer Party
    "CustomerParty.party_.partyIdentification_.iD": "CPID123456789",
    "CustomerParty.party_.partyName_.name": "Customer Name Ltd.",
    "CustomerParty.party_.postalAddress_.streetName": "789 Customer Ave.",
    "CustomerParty.party_.postalAddress_.cityName": "Customer City",
    "CustomerParty.party_.postalAddress_.postcode": "CC67890",
    "CustomerParty.party_.postalAddress_.countryIdentifier": "GB",

    // Purchase Receipt Line
    "PurchaseReceiptLine.item_.commodityClassification_.itemClassificationCode":
      "ICC67890",
    "PurchaseReceiptLine.item_.itemInstance_.additionalItemProperty.itemPropertyName":
      "Size",
    "PurchaseReceiptLine.item_.itemInstance_.additionalItemProperty.value":
      "Medium",
    "PurchaseReceiptLine.quantity": 2,
    "PurchaseReceiptLine.allowanceCharge_.amount": 5.0,
    "PurchaseReceiptLine.allowanceCharge_.allowanceChargeReason": "Promotion",
    "PurchaseReceiptLine.taxInclusiveLineExtentionAmount": 80.45,
    "PurchaseReceiptLine.iD": "PRL123456789",

    // Delivery
    "Delivery.actualDeliveryDate": "2024-04-28",
    "Delivery.deliveryAddress.streetName": "321 Delivery Rd.",
    "Delivery.deliveryAddress.cityName": "Delivery City",
    "Delivery.deliveryAddress.postcode": "DC12345",
    "Delivery.deliveryAddress.countryIdentifier": "GB",
    "Delivery.actualDeliveryTime": "14:30",

    // Document Reference
    "DocumentReference.iD": "DR123456789",

    // Item Instance
    "ItemInstance.additionalItemProperty.itemPropertyName": "Warranty",
    "ItemInstance.additionalItemProperty.value": "2 Years",
  };

  const disclosureFrame = {
    _sd: [
      "id",

      // Monetary Total
      "MonetaryTotal.lineExtensionAmount",
      "MonetaryTotal.taxInclusiveAmount",
      "MonetaryTotal.payableAmount",

      // Tax Total
      "TaxTotal.taxSubtotal_",
      "TaxTotal.taxAmount",

      // Address
      "Address.streetName",
      "Address.cityName",
      "Address.postcode",
      "Address.countryIdentifier",

      // Tax Category
      "TaxCategory.taxScheme_",

      // Item Property
      "ItemProperty.itemPropertyName",
      "ItemProperty.value",

      // Tax Scheme
      "TaxScheme.taxSchemeName",

      // Allowance Charge
      "AllowanceCharge.amount",
      "AllowanceCharge.allowanceChargeReason",

      // Party Name
      "PartyName.name",

      // Payment Means
      "PaymentMeans.cardAccount_",
      "PaymentMeans.paymentMeansCode",

      // Party Identification
      "PartyIdentification.iD",

      // Purchase Receipt
      "PurchaseReceipt.paymentMeans_",
      "PurchaseReceipt.note",
      "PurchaseReceipt.delivery_",
      "PurchaseReceipt.taxIncludedIndicator",
      "PurchaseReceipt.taxTotal_",
      "PurchaseReceipt.accountingCustomerParty_",
      "PurchaseReceipt.documentCurrencyCode",
      "PurchaseReceipt.payment_",
      "PurchaseReceipt.sellerSupplierParty",
      "PurchaseReceipt.legalMonetaryTotal",
      "PurchaseReceipt.salesDocumentReference",
      "PurchaseReceipt.iD",
      "PurchaseReceipt.issueDate",
      "PurchaseReceipt.purchaseReceiptLine-1",

      // Tax Subtotal
      "TaxSubtotal.taxableAmount",
      "TaxSubtotal.taxSubtotalTaxAmount",
      "TaxSubtotal.taxCategory_",
      "TaxSubtotal.percent",

      // Item
      "Item.commodityClassification_",
      "Item.itemInstance_",
      "Item.additionalItemProperty",

      // Payment
      "Payment.authorizationID",
      "Payment.paidAmount",
      "Payment.transactionID",

      // Supplier Party
      "SupplierParty.party_",
      "SupplierParty.supplierPartyID",

      // Party
      "Party.partyIdentification_.iD",
      "Party.partyName_.name",
      "Party.postalAddress_.streetName",
      "Party.postalAddress_.cityName",
      "Party.postalAddress_.postcode",
      "Party.postalAddress_.countryIdentifier",

      // Commodity Classification
      "CommodityClassification.itemClassificationCode",

      // Card Account
      "CardAccount.networkID",
      "CardAccount.accountNumberID",

      // Customer Party
      "CustomerParty.party_.partyIdentification_.iD",
      "CustomerParty.party_.partyName_.name",
      "CustomerParty.party_.postalAddress_.streetName",
      "CustomerParty.party_.postalAddress_.cityName",
      "CustomerParty.party_.postalAddress_.postcode",
      "CustomerParty.party_.postalAddress_.countryIdentifier",

      // Purchase Receipt Line
      "PurchaseReceiptLine.item_.commodityClassification_.itemClassificationCode",
      "PurchaseReceiptLine.item_.itemInstance_.additionalItemProperty.itemPropertyName",
      "PurchaseReceiptLine.item_.itemInstance_.additionalItemProperty.value",
      "PurchaseReceiptLine.quantity",
      "PurchaseReceiptLine.allowanceCharge_.amount",
      "PurchaseReceiptLine.allowanceCharge_.allowanceChargeReason",
      "PurchaseReceiptLine.taxInclusiveLineExtentionAmount",
      "PurchaseReceiptLine.iD",

      // Delivery
      "Delivery.actualDeliveryDate",
      "Delivery.deliveryAddress.streetName",
      "Delivery.deliveryAddress.cityName",
      "Delivery.deliveryAddress.postcode",
      "Delivery.deliveryAddress.countryIdentifier",
      "Delivery.actualDeliveryTime",

      // Document Reference
      "DocumentReference.iD",

      // Item Instance
      "ItemInstance.additionalItemProperty.itemPropertyName",
      "ItemInstance.additionalItemProperty.value",
    ],
  };

  return { claims, disclosureFrame };
};

export const getVReceiptSDJWTDataWithPayload = (
  payload,
  decodedHeaderSubjectDID
) => {
  if (!payload) {
    payload = {
      "MonetaryTotal.lineExtensionAmount": 150.0,
      "MonetaryTotal.taxInclusiveAmount": 180.0,
      "MonetaryTotal.payableAmount": 180.0,

      "TaxTotal.taxSubtotal_": [
        {
          "TaxSubtotal.taxableAmount": 150.0,
          "TaxSubtotal.taxSubtotalTaxAmount": 30.0,
          "TaxSubtotal.percent": 20,
          "TaxSubtotal.taxCategory_": {
            "TaxCategory.taxScheme_": {
              "TaxScheme.taxSchemeName": "VAT",
            },
          },
        },
      ],
      "TaxTotal.taxAmount": 30.0,

      "Address.streetName": "123 High Street",
      "Address.cityName": "London",
      "Address.postcode": "W1A 1AA",
      "Address.countryIdentifier": "GB",

      "ItemProperty.itemPropertyName": "Color",
      "ItemProperty.value": "Red",

      "PaymentMeans.cardAccount_": {
        "CardAccount.networkID": "VISA",
        "CardAccount.accountNumberID": "**** **** **** 6789",
      },
      "PaymentMeans.paymentMeansCode": "CreditCard",

      PurchaseReceipt: {
        iD: "PR-2023-456",
        issueDate: "2023-10-05",
        documentCurrencyCode: "GBP",
        note: "Thank you for your business!",

        delivery_: {
          "Delivery.actualDeliveryDate": "2023-10-06",
          "Delivery.deliveryAddress": {
            streetName: "456 Delivery Lane",
            cityName: "Manchester",
            postcode: "M1 1AB",
            countryIdentifier: "GB",
          },
          "Delivery.actualDeliveryTime": "14:30:00Z",
        },

        "purchaseReceiptLine-1": [
          {
            iD: "PRL-001",
            quantity: 2,
            item_: {
              commodityClassification_: {
                "CommodityClassification.itemClassificationCode": "HSCode123",
              },
              itemInstance_: {
                additionalItemProperty: {
                  itemPropertyName: "Size",
                  value: "Medium",
                },
              },
            },
            allowanceCharge_: {
              amount: 10.0,
              allowanceChargeReason: "Promotional Discount",
            },
            taxInclusiveLineExtentionAmount: 80.0,
          },
        ],
      },

      SupplierParty: {
        supplierPartyID: "SUP-789",
        party_: {
          "PartyIdentification.iD": "COMP-123",
          "PartyName.name": "Tech Supplies Ltd",
          postalAddress_: {
            streetName: "789 Business Rd",
            cityName: "Birmingham",
            postcode: "B2 4QA",
            countryIdentifier: "GB",
          },
        },
      },

      CustomerParty: {
        party_: {
          "partyIdentification_.iD": "CUST-123",
          "partyName_.name": "John Doe",
          postalAddress_: {
            streetName: "321 Consumer St",
            cityName: "Leeds",
            postcode: "LS1 4DW",
            countryIdentifier: "GB",
          },
        },
      },

      Payment: {
        authorizationID: "AUTH-789",
        paidAmount: 180.0,
        transactionID: "TX-2023-987",
      },

      "DocumentReference.iD": "INV-2023-789",
    };
  }

  const claims = {
    id: decodedHeaderSubjectDID || uuidv4(),
    ...payload,
  };

  const disclosureFrame = {
    _sd: [
      "id",

      // Monetary Total
      "MonetaryTotal.lineExtensionAmount",
      "MonetaryTotal.taxInclusiveAmount",
      "MonetaryTotal.payableAmount",

      // Tax Total
      "TaxTotal.taxSubtotal_",
      "TaxTotal.taxAmount",

      // Address
      "Address.streetName",
      "Address.cityName",
      "Address.postcode",
      "Address.countryIdentifier",

      // Tax Category
      "TaxCategory.taxScheme_",

      // Item Property
      "ItemProperty.itemPropertyName",
      "ItemProperty.value",

      // Tax Scheme
      "TaxScheme.taxSchemeName",

      // Allowance Charge
      "AllowanceCharge.amount",
      "AllowanceCharge.allowanceChargeReason",

      // Party Name
      "PartyName.name",

      // Payment Means
      "PaymentMeans.cardAccount_",
      "PaymentMeans.paymentMeansCode",

      // Party Identification
      "PartyIdentification.iD",

      // Purchase Receipt
      "PurchaseReceipt.paymentMeans_",
      "PurchaseReceipt.note",
      "PurchaseReceipt.delivery_",
      "PurchaseReceipt.taxIncludedIndicator",
      "PurchaseReceipt.taxTotal_",
      "PurchaseReceipt.accountingCustomerParty_",
      "PurchaseReceipt.documentCurrencyCode",
      "PurchaseReceipt.payment_",
      "PurchaseReceipt.sellerSupplierParty",
      "PurchaseReceipt.legalMonetaryTotal",
      "PurchaseReceipt.salesDocumentReference",
      "PurchaseReceipt.iD",
      "PurchaseReceipt.issueDate",
      "PurchaseReceipt.purchaseReceiptLine-1",

      // Tax Subtotal
      "TaxSubtotal.taxableAmount",
      "TaxSubtotal.taxSubtotalTaxAmount",
      "TaxSubtotal.taxCategory_",
      "TaxSubtotal.percent",

      // Item
      "Item.commodityClassification_",
      "Item.itemInstance_",
      "Item.additionalItemProperty",

      // Payment
      "Payment.authorizationID",
      "Payment.paidAmount",
      "Payment.transactionID",

      // Supplier Party
      "SupplierParty.party_",
      "SupplierParty.supplierPartyID",

      // Party
      "Party.partyIdentification_.iD",
      "Party.partyName_.name",
      "Party.postalAddress_.streetName",
      "Party.postalAddress_.cityName",
      "Party.postalAddress_.postcode",
      "Party.postalAddress_.countryIdentifier",

      // Commodity Classification
      "CommodityClassification.itemClassificationCode",

      // Card Account
      "CardAccount.networkID",
      "CardAccount.accountNumberID",

      // Customer Party
      "CustomerParty.party_.partyIdentification_.iD",
      "CustomerParty.party_.partyName_.name",
      "CustomerParty.party_.postalAddress_.streetName",
      "CustomerParty.party_.postalAddress_.cityName",
      "CustomerParty.party_.postalAddress_.postcode",
      "CustomerParty.party_.postalAddress_.countryIdentifier",

      // Purchase Receipt Line
      "PurchaseReceiptLine.item_.commodityClassification_.itemClassificationCode",
      "PurchaseReceiptLine.item_.itemInstance_.additionalItemProperty.itemPropertyName",
      "PurchaseReceiptLine.item_.itemInstance_.additionalItemProperty.value",
      "PurchaseReceiptLine.quantity",
      "PurchaseReceiptLine.allowanceCharge_.amount",
      "PurchaseReceiptLine.allowanceCharge_.allowanceChargeReason",
      "PurchaseReceiptLine.taxInclusiveLineExtentionAmount",
      "PurchaseReceiptLine.iD",

      // Delivery
      "Delivery.actualDeliveryDate",
      "Delivery.deliveryAddress.streetName",
      "Delivery.deliveryAddress.cityName",
      "Delivery.deliveryAddress.postcode",
      "Delivery.deliveryAddress.countryIdentifier",
      "Delivery.actualDeliveryTime",

      // Document Reference
      "DocumentReference.iD",

      // Item Instance
      "ItemInstance.additionalItemProperty.itemPropertyName",
      "ItemInstance.additionalItemProperty.value",
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
    // fundingSource: {
    //   type: "Credit Card", // Example funding source type
    //   panEndsIn: "1234", // Example PAN ends in
    //   iin: "400000", // Example IIN
    //   aliasId: "alias-12345", // Example alias ID
    //   scheme: "Visa", // Example card scheme
    //   icon: "https://cdn4.iconfinder.com/data/icons/flat-brand-logo-2/512/visa-512.png", // Example card icon URL
    // },
    accounts: ["123"], //
    account_holder_id: "luke skywalker", //
  };
  // Claims for the payload
  const claims = {
    aud: `${serverURL}/.well-known/oauth-authorization-server`,
    sub: "PSP-account-identifier", // Ensure consistency with 'id' in credentialSubject
    exp: expirationTime,
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
      family_name_unicode: "Doe",
      given_name_unicode: "Jane",
      birth_date: "01.07.2005",
      portrait: face_data,
      issue_date: "2023-01-01",
      expiry_date: "21.10.2027",
      issuing_authority_unicode: "Wonderland Authority",
      issuing_country: "FIN",
      sex: "2", // 0=unknown,1=male,2=female,9=not-applicable
      nationality: "FIN",
      document_number: "ABC1234567",
      name_at_birth: "Hanna Matkalainen",
      birthplace: "Wonder City",
      portrait_capture_date: "2023-02-01T10:00:00Z",
      resident_address_unicode: "123 Elm Street",
      resident_city_unicode: "Wonder City",
      resident_postal_code: "W12345",
      resident_country: "WL",
      age_over_18: true,
      age_in_years: 33,
      age_birth_year: 1990,
      family_name_latin1: "Matkalainen",
      given_name_latin1: "Hanna",
    },

    photoid: {
      person_id: "PERSON-98765",
      birth_country: "WL",
      birth_state: "Wonderland Province",
      birth_city: "Wonder City",
      administrative_number: "ADMIN-123",
      resident_street: "123 Elm Street",
      resident_house_number: "12",
      travel_document_number: "XP8271602",
      resident_state: "Wonderland Province",
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
    iso23220: {
      _sd: [
        "family_name_unicode",
        "given_name_unicode",
        "birth_date",
        "portrait",
        "issue_date",
        "expiry_date",
        "issuing_authority_unicode",
        "issuing_country",
        "sex",
        "nationality",
        "document_number",
        "name_at_birth",
        "birthplace",
        "portrait_capture_date",
        "resident_address_unicode",
        "resident_city_unicode",
        "resident_postal_code",
        "resident_country",
        "age_over_18",
        "age_in_years",
        "age_birth_year",
        "family_name_latin1",
        "given_name_latin1",
      ],
    },
    photoid: {
      _sd: [
        "person_id",
        "birth_country",
        "birth_state",
        "birth_city",
        "administrative_number",
        "resident_street",
        "resident_house_number",
        "travel_document_number",
        "resident_state",
      ],
    },
    dtc: {
      _sd: [
        "dtc_version",
        "dtc_dg1",
        "dtc_dg2",
        "dtc_sod",
        "dtc_dg3",
        "dtc_dg4",
        "dtc_dg16",
        "dg_content_info",
      ],
    },
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
