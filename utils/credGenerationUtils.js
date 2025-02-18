/**
 * Extracted function for issuing a VC+SD-JWT credential.
 *
 * @param {object} params
 * @param {object} params.requestBody - The incoming request body (containing `vct`, `proof`, etc.)
 * @param {object} [params.sessionObject] - Session object containing e.g. `isHaip` or custom payload
 * @param {function} params.createSignerVerifier - Function to create signer/verifier from JWK
 * @param {function} params.pemToJWK - Utility to convert PEM to JWK
 * @param {function} params.generateSalt - Salt generator for SD-JWT
 * @param {function} params.digest - Hash function for SD-JWT
 * @param {string} params.privateKey - The issuer's private key in PEM form
 * @param {string} params.publicKeyPem - The issuer's public key in PEM form
 * @param {string} params.serverURL - Issuer/Server URL
 * @param {string} [params.certificatePemX509] - X.509 certificate PEM (if HAIP flow)
 * @param {function} params.generateNonce - Function that generates a cryptographic nonce
 * @param {function} params.didKeyToJwks - Utility to convert a DID key to a JWKS
 * @param {object} params.jwt - The 'jsonwebtoken' library or an equivalent with a 'decode' function
 * @param {object} params.SDJwtVcInstance - The class used to instantiate SD-JWT VCs
 *
 * @returns {Promise<object>} An object that can be returned via res.json(...)
 */
export async function generateVcSdJwtCredential({
    requestBody,
    sessionObject,
    createSignerVerifier,
    pemToJWK,
    generateSalt,
    digest,
    privateKey,
    publicKeyPem,
    serverURL,
    certificatePemX509,
    generateNonce,
    didKeyToJwks,
    jwt,
    SDJwtVcInstance,
  }) {
    // For example: VerifiablePortableDocumentA1SDJWT, VerifiablePortableDocumentA2SDJWT, etc.
    const credType = requestBody.vct;
    console.log("vc+sd-jwt ", credType);
  
    if (!requestBody.proof || !requestBody.proof.jwt) {
      // If there's no proof, throw an error so the caller can handle an HTTP 400
      throw new Error("proof not found");
    }
  
    // Decode holder's proof JWT to get the holder's JWK(s)
    const decodedWithHeader = jwt.decode(requestBody.proof.jwt, {
      complete: true,
    });
    const holderJWKS = decodedWithHeader.header;
  
    // If sessionObject indicates a HAIP flow, we sign with an X509 certificate
    const isHaip = sessionObject ? sessionObject.isHaip : false;
  
    // Instantiate the SD-JWT instance
    let sdjwt;
    if (isHaip) {
      // If you already have { signer, verifier } in scope, you can skip createSignerVerifier
      // This snippet assumes they are accessible
      sdjwt = new SDJwtVcInstance({
        signer,
        verifier,
        signAlg: "ES256",
        hasher: digest,
        hashAlg: "sha-256",
        saltGenerator: generateSalt,
      });
    } else {
      // If not HAIP, create signer/verifier from the private/public key PEM
      const { signer, verifier } = await createSignerVerifier(
        pemToJWK(privateKey, "private"),
        pemToJWK(publicKeyPem, "public")
      );
      sdjwt = new SDJwtVcInstance({
        signer,
        verifier,
        signAlg: "ES256",
        hasher: digest,
        hashAlg: "sha-256",
        saltGenerator: generateSalt,
      });
    }
  
    // Build the credential payload dynamically based on credType
    let credPayload = {};
    try {
      if (
        credType === "VerifiablePIDSDJWT" ||
        credType === "urn:eu.europa.ec.eudi:pid:1"
      ) {
        credPayload = getPIDSDJWTData();
      } else if (credType === "VerifiableePassportCredentialSDJWT") {
        credPayload = getEPassportSDJWTData();
      } else if (credType === "VerifiableStudentIDSDJWT") {
        credPayload = getStudentIDSDJWTData();
      } else if (
        credType === "ferryBoardingPassCredential" ||
        credType === "VerifiableFerryBoardingPassCredentialSDJWT"
      ) {
        credPayload = await getFerryBoardingPassSDJWTData();
      } else if (credType === "VerifiablePortableDocumentA1SDJWT") {
        credPayload = getGenericSDJWTData();
      }
  
      if (credType === "PaymentWalletAttestation") {
        credPayload = createPaymentWalletAttestationPayload();
      } else if (credType === "VerifiablevReceiptSDJWT") {
        if (sessionObject) {
          credPayload = getVReceiptSDJWTDataWithPayload(
            sessionObject.credentialPayload
          );
        } else {
          credPayload = getVReceiptSDJWTData();
        }
      } else if (credType === "VerifiablePortableDocumentA2SDJWT") {
        credPayload = getGenericSDJWTData();
      } else if (credType === "eu.europa.ec.eudi.photoid.1") {
        credPayload = createPhotoIDAttestationPayload();
      } else if (credType === "eu.europa.ec.eudi.pcd.1") {
        credPayload = createPCDAttestationPayload();
      }
  
      // Attach the holder's JWK to the credential
      let cnf = { jwk: holderJWKS.jwk };
      if (!cnf.jwk) {
        // Alternatively, fetch the JWK from a DID
        cnf = await didKeyToJwks(holderJWKS.kid);
      }
  
      // Construct the final credential
      let credential;
      if (isHaip) {
        console.log("HAIP issue flow.. will add x509 header");
        console.log("client certificate pem is");
        console.log(certificatePemX509);
  
        const certBase64 = pemToBase64Der(certificatePemX509);
        const x5cHeader = [certBase64];
  
        // Create an SD-JWT with X.509 header
        credential = await sdjwt.issue(
          {
            iss: serverURL,
            iat: Math.floor(Date.now() / 1000),
            vct: credType,
            ...credPayload.claims,
            cnf,
          },
          credPayload.disclosureFrame,
          {
            header: { x5c: x5cHeader },
          }
        );
      } else {
        // Create an SD-JWT with a typical 'kid' header
        credential = await sdjwt.issue(
          {
            iss: serverURL,
            iat: Math.floor(Date.now() / 1000),
            vct: credType,
            ...credPayload.claims,
            cnf,
          },
          credPayload.disclosureFrame,
          {
            header: { kid: "aegean#authentication-key" },
          }
        );
      }
  
      console.log("sending credential");
      console.log({
        format: "vc+sd-jwt",
        credential,
        c_nonce: generateNonce(),
        c_nonce_expires_in: 86400,
      });
  
      // Return the object that can be directly JSON-stringified
      return {
        format: "vc+sd-jwt",
        credential,
        c_nonce: generateNonce(),
        c_nonce_expires_in: 86400,
      };
    } catch (error) {
      console.error("Error while issuing vc+sd-jwt:", error);
      throw error;
    }
  }
  