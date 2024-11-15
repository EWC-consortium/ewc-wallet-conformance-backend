import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
// import {ES384,digest,generateSalt} from "./sdjwtES384.js"
export { digest, generateSalt };
import { pem2jwk } from 'pem-jwk';
import forge from 'node-forge';
import fs from 'fs';

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
  // Convert private key PEM to JWK
  const privateKeyJWK = pem2jwk(privateKeyPem);

  // Extract public key from X.509 certificate
  const cert = forge.pki.certificateFromPem(certificatePem);
  const publicKeyPem = forge.pki.publicKeyToPem(cert.publicKey);

  // Convert public key PEM to JWK
  const publicKeyJWK = pem2jwk(publicKeyPem);

  // Set key operations and usage
  privateKeyJWK['key_ops'] = ['sign'];
  privateKeyJWK['use'] = 'sig';
  privateKeyJWK['ext'] = true;

  publicKeyJWK['key_ops'] = ['verify'];
  publicKeyJWK['ext'] = true;

  return {
    signer: await ES256.getSigner(privateKeyJWK),
    verifier: await ES256.getVerifier(publicKeyJWK),
  };
};