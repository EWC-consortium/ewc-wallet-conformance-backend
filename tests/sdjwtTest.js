import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";


async function test() {
    let sdjwt =
    "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJodHRwczovLzk2ZDYtMmEwMi01ODctODcxOS00NTAwLTFlMGItN2VmMS1mMDZmLTdjMmMubmdyb2stZnJlZS5hcHAiLCJpYXQiOjE3MTIzMDY4MDY5NjMsInZjdCI6IlZlcmlmaWFibGVQb3J0YWJsZURvY3VtZW50QTEiLCJfc2QiOlsiMTNoV01obHNiWS1ENG5MdTM0SFl4aHphQkFwVFo1Um52OUszOExvRkJYVSIsIlpaQl9Dc0hnVC10YWhkSUVoMUV1VjNsdUlHZlF5b245SjNsM0tTTXI0WXMiXSwiX3NkX2FsZyI6IlNIQS0yNTYifQ.P-u7sgprT5E4qx55mS8cioXPJ4pEnEOTLEQrJUzTTaZpyUdiVa6YQsy-Uvb5nzTtUYwZ6MfbZR7IhmdZiKg6SA  ~WyJlOGFiYjQzMDNiZjAyNTNmIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ  ~WyI4NDVjNzM3NGM5OTgwM2IxIiwibGFzdF9uYW1lIiwiRG9lIl0~";
  
  const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
  console.log("The decoded SD JWT is:");
  console.log(JSON.stringify(decodedSdJwt, null, 2));
  console.log(
    "================================================================"
  );
  // Get the claims from the SD JWT
  const claims = await getClaims(
    decodedSdJwt.jwt.payload,
    decodedSdJwt.disclosures,
    digest
  );

  console.log("The claims are:");
  console.log(JSON.stringify(claims, null, 2));
}

test();
