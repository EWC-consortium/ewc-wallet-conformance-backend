import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
// import {ES384,digest,generateSalt} from "./sdjwtES384.js"
export { digest, generateSalt };
import { pem2jwk } from 'pem-jwk';
import forge from 'node-forge';
import fs from 'fs';

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