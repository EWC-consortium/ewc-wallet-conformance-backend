import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
// import {ES384,digest,generateSalt} from "./sdjwtES384.js"
export { digest, generateSalt };
import { pem2jwk } from 'pem-jwk';
import forge from 'node-forge';
import fs from 'fs';
import base64url from 'base64url'


import { importPKCS8, importX509, exportJWK } from 'jose';


export const createSignerVerifier = async (privateKey, publicKey) => {
  // const { privateKey, publicKey } = await ES256.generateKeyPair();


  privateKey["key_ops"] = [ 'sign' ]
  privateKey["use"] = "sig"
  privateKey["ext"] = true
   

  publicKey["key_ops"] = [ 'verify' ]
  publicKey["ext"] = true


  return {
    signer: await ES256.getSigner(privateKey),
    verifier: await ES256.getVerifier(publicKey),
  };
  console.log(privateKey)
  console.log("<----------->")
  console.log(publicKey)

};


export const createSignerVerifierX509 = async (privateKeyPem, certificatePem) => {
  try {
    // Import the private key using jose
    const privateKey = await importPKCS8(privateKeyPem, 'ES256');

    // Import the public key from the certificate using jose
    const publicKey = await importX509(certificatePem, 'ES256');

    // Export the keys to JWK format
    const privateKeyJWK = await exportJWK(privateKey);
    const publicKeyJWK = await exportJWK(publicKey);

    // Set key operations and usage flags
    privateKeyJWK.key_ops = ['sign'];
    privateKeyJWK.use = 'sig';
    privateKeyJWK.ext = true;

    publicKeyJWK.key_ops = ['verify'];
    publicKeyJWK.ext = true;

    // Obtain signer and verifier using ES256 library functions
    const signer = await ES256.getSigner(privateKeyJWK);
    const verifier = await ES256.getVerifier(publicKeyJWK);

    return { signer, verifier };
  } catch (error) {
    console.error('Error creating signer and verifier:', error);
    throw error;
  }
};



/**
 * Extracts and merges claims from the _sd array in the decoded SD-JWT.
 *
 * @param {Object} decodedSdJwt - The decoded SD-JWT object.
 * @returns {Object} - The reconstructed claims object.
 */
export function extractClaims(decodedSdJwt) {
  const sdArray = decodedSdJwt['_sd'];

  if (!sdArray || !Array.isArray(sdArray)) {
    throw new Error("Invalid SD-JWT: '_sd' field is missing or not an array.");
  }

  let claims = {};

  sdArray.forEach((sdSegment, index) => {
    try {
      // Decode the base64url-encoded segment
      const decoded = base64url.toBuffer(sdSegment).toString('utf-8');

      // Parse the JSON string into an object
      const claimSegment = JSON.parse(decoded);

      // Merge the claim segment into the claims object
      claims = { ...claims, ...claimSegment };
    } catch (error) {
      console.error(`Error decoding _sd segment at index ${index}:`, error);
      throw new Error(`Failed to decode _sd segment at index ${index}.`);
    }
  });

  return claims;
}