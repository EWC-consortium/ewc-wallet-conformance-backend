import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
// import {ES384,digest,generateSalt} from "./sdjwtES384.js"
export { digest, generateSalt };

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