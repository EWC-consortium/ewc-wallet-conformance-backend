import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";
import jwt from "jsonwebtoken";

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


async function test2(){

  let t = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJ4NWMiOlsiTUlJQjlEQ0NBWnVnQXdJQkFnSVVjSXZsdVhlSzQvZFIxL3FsZjhuTEJJR2xsR0l3Q2dZSUtvWkl6ajBFQXdJd1VERUxNQWtHQTFVRUJoTUNSMUl4Q3pBSkJnTlZCQWdNQWtkU01SQXdEZ1lEVlFRS0RBZFZRV1ZuWldGdU1SQXdEZ1lEVlFRTERBZFZRV1ZuWldGdU1SQXdEZ1lEVlFRRERBZFZRV1ZuWldGdU1CNFhEVEkwTVRJeE1URTBNVGt4TlZvWERUSTFNVEl4TVRFME1Ua3hOVm93VURFTE1Ba0dBMVVFQmhNQ1IxSXhDekFKQmdOVkJBZ01Ba2RTTVJBd0RnWURWUVFLREFkVlFXVm5aV0Z1TVJBd0RnWURWUVFMREFkVlFXVm5aV0Z1TVJBd0RnWURWUVFEREFkVlFXVm5aV0Z1TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFZE1MdE1ITStiWWRpSlJISm1mQTd5cGloUzhKREFtY2k0cTNGT2VMeTZtRHhsZUhkMDZ3dWdrVlBWam9YNzRlQkhxNEdPdzZKK2RNaUtKV2RCK0NoYTZOVE1GRXdIUVlEVlIwT0JCWUVGRlNLVzlVZVd3WlFxZWhGK0kyVlM4SjlwU2ZMTUI4R0ExVWRJd1FZTUJhQUZGU0tXOVVlV3daUXFlaEYrSTJWUzhKOXBTZkxNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdDZ1lJS29aSXpqMEVBd0lEUndBd1JBSWdBT3Q5d1Q4TnBiWjFaQ3NIcGg5amtmME1rK2xGN293UUVldFFoQ1hIZ3dRQ0lGbnM2SGlWempNQ29UbTJWcHJMYlcwcm9FaEd3azdpN2phaStyTXAzQmMwIl0sImFsZyI6IkVTMjU2In0.eyJpc3MiOiJodHRwczovL2Rzcy5hZWdlYW4uZ3IvcmZjLWlzc3VlciIsImlhdCI6MTczODk0MDkwOCwidmN0IjoiVmVyaWZpYWJsZVBvcnRhYmxlRG9jdW1lbnRBMVNESldUIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlJLWTVRelRRdDM0enFFaGdwdFFhRjZHU1l1dDgwbkZSbEk5bDZtcWllX1kiLCJ5IjoiR18yMmd4RTJhVUctdUNwRm5NWVFpaWctYS13T3piVmQ3TWdxS002cXRKNCJ9fSwiX3NkIjpbIjVHVHpNaXcxekE2RmluRkVWa21kTjEtb2RWUDFMdE5tWDZ3czlIRmNuaEUiLCJ1MTk0V3FKOFhjdGtSNnJYSnRNQ2xJakhXeEVCNk1mY08zc2d4V2twRXljIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.2yJVUlh8wqkgiSk3zVFEQVb-Urb_m1Vre7u9gcmd9cuo3LhobHyO4Fr7a85TT2DDSN-8ih4pQ1Dg6du8j7boqg~WyI2NWY3YmU0NDU5ZGQzMTFlIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJkNWNjZjcyY2VmN2M3ZmQ4IiwibGFzdF9uYW1lIiwiRG9lIl0~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJkc3MuYWVnZWFuLmdyIiwibm9uY2UiOiIxMzE2NmUzNmUyZGVlYmEyMTI1YzQ0ZDU3YjY5ZDU1MyIsImlhdCI6MTczOTI3MDYzNCwic2RfaGFzaCI6Ink4cUg1c2Vhc0sxQUhzNDZtdDA1Wk1rWUxCbWFXRHhpM3VpZTNRRGVKTG8ifQ.aatPEmWuXbatyThEp0drG3uNTl6bXHU0LJTiCLT3i1_n_Fvwee4K5Urudk89a5RNKbJWtLp4YJKd8Cj0M_pJUA"
  let res =  await jwt.decode(t, { complete: true })
  console.log(res)  

}

test2();
