import * as jose from "jose";
import jwt from "jsonwebtoken";
import { publicKeyToPem } from "../routes/issue/sharedIssuanceFlows.js";
import { strict as assert } from "assert";

describe("publicKeyToPem", () => {
  it("should correctly convert an RSA JWK from a JWT header to PEM format", async () => {
    // 1. Generate an RSA key pair
    const { publicKey, privateKey } = await jose.generateKeyPair("RS256");
    const publicJwk = await jose.exportJWK(publicKey);

    // 2. Create a JWT with the public key (as a JWK) in the header
    const payload = {
      sub: "1234567890",
      name: "John Doe",
      iat: Math.floor(Date.now() / 1000),
    };

    const privateJwk = await jose.exportJWK(privateKey);
    const privateKeyForSigning = await jose.importJWK(privateJwk, "RS256");

    const token = await new jose.SignJWT(payload)
      .setProtectedHeader({
        alg: "RS256",
        jwk: publicJwk,
      })
      .setIssuedAt()
      .setSubject("urn:example:subject")
      .setIssuer("urn:example:issuer")
      .setAudience("urn:example:audience")
      .sign(privateKeyForSigning);

    // 3. Decode the JWT to extract the JWK
    const decodedProofHeader = jwt.decode(token, { complete: true })?.header;
    const publicKeyForProof = decodedProofHeader.jwk;

    assert.ok(
      publicKeyForProof,
      "JWK should be present in the decoded header"
    );

    // 4. Call publicKeyToPem with the extracted JWK
    const pemKey = await publicKeyToPem(publicKeyForProof);

    // 5. Verify that the result is a valid PEM-formatted public key
    assert.ok(pemKey, "The result should not be empty");
    assert.strictEqual(typeof pemKey, "string", "The result should be a string");
    assert.ok(
      pemKey.startsWith("-----BEGIN PUBLIC KEY-----"),
      "PEM string should start with the correct header"
    );
    assert.ok(
      pemKey.endsWith("-----END PUBLIC KEY-----\n") ||
        pemKey.endsWith("-----END PUBLIC KEY-----"),
      "PEM string should end with the correct footer"
    );

    console.log("Successfully converted RSA JWK to PEM:", pemKey);
  });

  it("should correctly convert an EC P-256 JWK from a JWT header to PEM format", async () => {
    // 1. Generate an EC key pair
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const publicJwk = await jose.exportJWK(publicKey);

    // 2. Create a JWT with the public key (as a JWK) in the header
    const payload = {
      sub: "1234567890",
      name: "Jane Doe",
      iat: Math.floor(Date.now() / 1000),
    };

    const privateKeyForSigning = await jose.importJWK(
      await jose.exportJWK(privateKey),
      "ES256"
    );

    const token = await new jose.SignJWT(payload)
      .setProtectedHeader({
        alg: "ES256",
        jwk: publicJwk,
      })
      .setIssuedAt()
      .sign(privateKeyForSigning);

    // 3. Decode the JWT to extract the JWK
    const decodedProofHeader = jwt.decode(token, { complete: true })?.header;
    const publicKeyForProof = decodedProofHeader.jwk;

    assert.ok(
      publicKeyForProof,
      "JWK should be present in the decoded header"
    );

    // 4. Call publicKeyToPem with the extracted JWK
    const pemKey = await publicKeyToPem(publicKeyForProof);

    // 5. Verify that the result is a valid PEM-formatted public key
    assert.ok(pemKey, "The result should not be empty");
    assert.strictEqual(typeof pemKey, "string", "The result should be a string");
    assert.ok(
      pemKey.startsWith("-----BEGIN PUBLIC KEY-----"),
      "PEM string should start with the correct header"
    );
    assert.ok(
      pemKey.endsWith("-----END PUBLIC KEY-----\n") ||
        pemKey.endsWith("-----END PUBLIC KEY-----"),
      "PEM string should end with the correct footer"
    );

    console.log("Successfully converted EC P-256 JWK to PEM:", pemKey);
  });

  it.skip("should correctly convert the provided Google JWT's JWK to PEM format", async () => {
    const googleToken =
      "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiNXFBd3lRb3VOLUhwQ09wN3dacV9Sc0RmVTEzZVgtSEJnMmFuaTVYUlRlWSIsInkiOiJwOTZtM1p3ZmU0X2hOdXFibldLSVd2c3ZpSnVDYm9QWDFwa2hCUTIydjNBIn19.eyJhdWQiOiJodHRwczovL2Rzcy5hZWdlYW4uZ3IvcmZjLWlzc3VlciIsImlhdCI6MTc0NTUxNTg2Nywibm9uY2UiOiI2ZTRmM2ZlOGMwMzFjZWJlOWEzY2ZlNWEifQ.J9Y9by8vodiaXBPOAj_ZooxfYbTqRofQJasmHl_Q9PATipno-oNjJOrjzYMmF4Fu_B4QWxlmjsH--cYH40NMxQ";

    const decodedProofHeader = jwt.decode(googleToken, {
      complete: true,
    })?.header;
    const publicKeyForProof = decodedProofHeader.jwk;

    assert.ok(
      publicKeyForProof,
      "JWK should be present in the decoded header"
    );

    const pemKey = await publicKeyToPem(publicKeyForProof);

    assert.ok(pemKey, "The result should not be empty");
    assert.strictEqual(typeof pemKey, "string", "The result should be a string");
    assert.ok(
      pemKey.startsWith("-----BEGIN PUBLIC KEY-----"),
      "PEM string should start with the correct header"
    );
    assert.ok(
      pemKey.endsWith("-----END PUBLIC KEY-----\n") ||
        pemKey.endsWith("-----END PUBLIC KEY-----"),
      "PEM string should end with the correct footer"
    );

    console.log("Successfully converted Google JWT's JWK to PEM:", pemKey);
  });
}); 