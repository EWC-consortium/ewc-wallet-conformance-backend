import crypto from "crypto";
import jwt from "jsonwebtoken";
import { importSPKI, exportJWK } from "jose";
import base64url from "base64url";
import { error } from "console";
import fs from "fs";



export async function convertPemToJwk() {
  const spki = fs.readFileSync('./didjwks/did_public.pem', 'utf8');
  const key = await importSPKI(spki, 'ES256');
  const jwk = await exportJWK(key);
  return jwk
//   console.log(JSON.stringify(jwk, null, 2));
}