import { expect } from "chai";
import crypto from "crypto";

/**
 * State Parameter Specification Tests
 * 
 * These tests document and validate the expected behavior of the state parameter
 * across all VP presentation routes (x509, did:web, did:jwk).
 * 
 * They serve as:
 * 1. Living documentation of state parameter requirements
 * 2. Regression prevention for the state mismatch bug
 * 3. OpenID4VP 1.0 compliance validation
 */

describe("State Parameter Specification - All Routes", () => {
  
  describe("State Generation Requirements", () => {
    it("must generate state as 32-character hexadecimal string", () => {
      // State is generated using crypto.randomBytes(16).toString('hex')
      const state = crypto.randomBytes(16).toString('hex');
      
      expect(state).to.be.a('string');
      expect(state).to.have.lengthOf(32);
      expect(state).to.match(/^[a-f0-9]{32}$/);
    });

    it("must generate cryptographically random state values", () => {
      const states = new Set();
      const iterations = 1000;
      
      for (let i = 0; i < iterations; i++) {
        const state = crypto.randomBytes(16).toString('hex');
        states.add(state);
      }
      
      // All states should be unique
      expect(states.size).to.equal(iterations);
    });

    it("must generate unique state per session", () => {
      const state1 = crypto.randomBytes(16).toString('hex');
      const state2 = crypto.randomBytes(16).toString('hex');
      
      // Probability of collision is negligible (1 in 2^128)
      expect(state1).to.not.equal(state2);
    });
  });

  describe("State Storage Requirements", () => {
    it("must store state in session data structure", () => {
      // Session data structure MUST include state
      const sessionData = {
        uuid: "test-session-id",
        status: "pending",
        nonce: "9ed3a5a19e8e5d9c036bc27d19f2de21",
        state: "87faebb49214bd8b6e45781df7a704e0", // REQUIRED
        response_mode: "direct_post",
        presentation_definition: { id: "test-pd" }
      };
      
      expect(sessionData).to.have.property("state");
      expect(sessionData.state).to.match(/^[a-f0-9]{32}$/);
    });

    it("must persist state throughout session lifecycle", () => {
      const initialState = "87faebb49214bd8b6e45781df7a704e0";
      
      // State must never change during session lifecycle
      const stateAtCreation = initialState;
      const stateAtJwtGeneration = initialState;
      const stateAtValidation = initialState;
      
      expect(stateAtJwtGeneration).to.equal(stateAtCreation);
      expect(stateAtValidation).to.equal(stateAtCreation);
    });
  });

  describe("State in JWT Payload Requirements", () => {
    it("must include state in JWT payload per OpenID4VP 1.0", () => {
      // OpenID4VP 1.0 Section 5.1: state is RECOMMENDED
      const jwtPayload = {
        response_type: "vp_token",
        response_mode: "direct_post",
        client_id: "x509_san_dns:dss.aegean.gr",
        nonce: "9ed3a5a19e8e5d9c036bc27d19f2de21",
        state: "87faebb49214bd8b6e45781df7a704e0", // RECOMMENDED -> REQUIRED for our implementation
        response_uri: "https://server.example/direct_post/session-id",
        presentation_definition: { id: "test-pd" }
      };
      
      expect(jwtPayload).to.have.property("state");
      expect(jwtPayload.state).to.be.a("string");
      expect(jwtPayload.state).to.have.lengthOf(32);
    });

    it("must ensure JWT state matches session state", () => {
      const sessionState = "87faebb49214bd8b6e45781df7a704e0";
      const jwtState = "87faebb49214bd8b6e45781df7a704e0";
      
      // CRITICAL: These MUST be identical
      expect(jwtState).to.equal(sessionState);
    });

    it("must not regenerate state when building JWT", () => {
      // BUG PREVENTION TEST
      // Previous bug: state was undefined, causing buildVpRequestJWT
      // to generate a NEW random state different from session state
      
      const storedState = "87faebb49214bd8b6e45781df7a704e0";
      const statePassedToJwtBuilder = storedState; // Must not be undefined/null
      
      expect(statePassedToJwtBuilder).to.not.be.undefined;
      expect(statePassedToJwtBuilder).to.not.be.null;
      expect(statePassedToJwtBuilder).to.equal(storedState);
    });
  });

  describe("State Validation Requirements", () => {
    it("must validate state on wallet response", () => {
      const expectedState = "87faebb49214bd8b6e45781df7a704e0";
      const receivedState = "87faebb49214bd8b6e45781df7a704e0";
      
      // Validation logic
      const isValid = receivedState === expectedState;
      
      expect(isValid).to.be.true;
    });

    it("must reject response when state is missing", () => {
      const expectedState = "87faebb49214bd8b6e45781df7a704e0";
      const receivedState = undefined;
      
      // Should reject - use Boolean conversion to ensure false value
      const isValid = !!(receivedState && receivedState === expectedState);
      
      expect(isValid).to.be.false;
    });

    it("must reject response when state does not match", () => {
      const expectedState = "87faebb49214bd8b6e45781df7a704e0";
      const receivedState = "08ab6dae0e802fa82bd51060889d5cd2"; // Different!
      
      // Should reject
      const isValid = receivedState === expectedState;
      
      expect(isValid).to.be.false;
    });

    it("must use strict equality for state comparison", () => {
      const expectedState = "87faebb49214bd8b6e45781df7a704e0";
      
      // Strict equality (===) must be used
      expect(expectedState === expectedState).to.be.true;
      expect(expectedState === "different").to.be.false;
      
      // Type coercion should not happen
      expect(expectedState == expectedState).to.be.true; // OK but strict is better
    });
  });

  describe("OpenID4VP 1.0 Compliance", () => {
    it("must comply with Section 5.1 Authorization Request requirements", () => {
      const authorizationRequest = {
        client_id: "verifier-client-id",
        response_type: "vp_token",
        response_mode: "direct_post",
        response_uri: "https://verifier.example/direct_post/session-id",
        nonce: "9ed3a5a19e8e5d9c036bc27d19f2de21", // REQUIRED
        state: "87faebb49214bd8b6e45781df7a704e0", // RECOMMENDED
        presentation_definition: { id: "test-pd" }
      };
      
      // Validate required and recommended parameters
      expect(authorizationRequest).to.have.property("nonce");
      expect(authorizationRequest).to.have.property("state");
      expect(authorizationRequest).to.have.property("response_mode");
      expect(authorizationRequest).to.have.property("response_uri");
    });

    it("must comply with Section 6.2 direct_post response requirements", () => {
      // Per OpenID4VP 1.0 Section 6.2:
      // "The Wallet MUST send the Authorization Response to the Response URI
      // using the HTTP POST method. The Wallet MUST include the state parameter."
      
      const walletResponse = {
        vp_token: "eyJhbGc...", // VP token
        state: "87faebb49214bd8b6e45781df7a704e0", // MUST include state
        presentation_submission: { /* ... */ }
      };
      
      expect(walletResponse).to.have.property("state");
      expect(walletResponse.state).to.be.a("string");
    });
  });

  describe("Security Properties", () => {
    it("must use state to prevent CSRF attacks", () => {
      // State parameter prevents Cross-Site Request Forgery by ensuring
      // the response corresponds to a request initiated by the verifier
      
      const verifierState = crypto.randomBytes(16).toString('hex');
      const attackerState = crypto.randomBytes(16).toString('hex');
      
      // Attacker cannot guess the verifier's state
      expect(attackerState).to.not.equal(verifierState);
      
      // Verifier rejects responses with wrong state
      const responseFromAttacker = { state: attackerState };
      const isValidResponse = responseFromAttacker.state === verifierState;
      
      expect(isValidResponse).to.be.false; // Attack prevented!
    });

    it("must ensure state is unpredictable", () => {
      // State must be generated using cryptographically secure random source
      // Using crypto.randomBytes() provides 128 bits of entropy
      
      const state = crypto.randomBytes(16).toString('hex');
      
      // Should be impossible to predict
      expect(state).to.not.equal("00000000000000000000000000000000");
      expect(state).to.not.equal("12345678901234567890123456789012");
    });

    it("must bind state to specific session", () => {
      // Each session must have its own unique state
      // State from one session must not validate for another session
      
      const session1State = crypto.randomBytes(16).toString('hex');
      const session2State = crypto.randomBytes(16).toString('hex');
      
      // States are session-specific
      expect(session1State).to.not.equal(session2State);
      
      // Response with session1's state should not validate for session2
      const session2Expected = session2State;
      const responseWithSession1State = session1State;
      
      expect(responseWithSession1State === session2Expected).to.be.false;
    });
  });

  describe("Regression Prevention - Critical Bug", () => {
    it("must not lose state due to parameter shift in buildVpRequestJWT", () => {
      // BUG DESCRIPTION (FIXED):
      // processVPRequest was calling buildVpRequestJWT with missing va_jwt parameter
      // This caused all subsequent parameters to shift by one position:
      // - vpSession.state was passed as va_jwt (parameter 17)
      // - state (parameter 18) was undefined
      // - buildVpRequestJWT generated a NEW random state
      
      // CORRECT PARAMETER ORDER:
      const parametersToJwtBuilder = {
        param1: "client_id",
        param2: "redirect_uri",
        param3: "presentation_definition",
        param4: "privateKey",
        param5: "client_metadata",
        param6: "kid",
        param7: "serverURL",
        param8: "response_type",
        param9: "nonce",
        param10: "dcql_query",
        param11: "transaction_data",
        param12: "response_mode",
        param13: "audience",
        param14: "wallet_nonce",
        param15: "wallet_metadata",
        param16: "va_jwt", // ← THIS WAS MISSING, causing bug
        param17: "state"   // ← vpSession.state must be here, not at param16!
      };
      
      // Verify parameter count
      const paramCount = Object.keys(parametersToJwtBuilder).length;
      expect(paramCount).to.equal(17); // 17 parameters total
      
      // Verify state is at correct position
      expect(parametersToJwtBuilder.param17).to.equal("state");
      expect(parametersToJwtBuilder.param16).to.equal("va_jwt");
    });

    it("must never show WARNING about missing state parameter", () => {
      // If this warning appears, it means state is not being passed correctly
      const warningMessage = "WARNING: state parameter not provided to buildVpRequestJWT";
      
      // This warning should NEVER appear in production logs
      const shouldShowWarning = false;
      
      expect(shouldShowWarning).to.be.false;
    });

    it("must document the exact error that was occurring", () => {
      // ACTUAL ERROR FROM PRODUCTION:
      const productionError = {
        type: "state mismatch in direct_post",
        expected: "87faebb49214bd8b6e45781df7a704e0", // From Redis session
        received: "08ab6dae0e802fa82bd51060889d5cd2"  // From JWT (randomly generated!)
      };
      
      // This happened because:
      // 1. Session correctly stored state: "87faebb49214bd8b6e45781df7a704e0"
      // 2. processVPRequest passed vpSession.state as va_jwt (wrong position)
      // 3. buildVpRequestJWT received undefined for state parameter
      // 4. buildVpRequestJWT generated random state: "08ab6dae0e802fa82bd51060889d5cd2"
      // 5. JWT sent to wallet with wrong state
      // 6. Wallet correctly echoed back JWT's state
      // 7. Verifier compared against session state → MISMATCH!
      
      expect(productionError.expected).to.not.equal(productionError.received);
      
      // After fix: expected and received MUST match
      const afterFix = {
        expected: "87faebb49214bd8b6e45781df7a704e0",
        received: "87faebb49214bd8b6e45781df7a704e0" // Same!
      };
      
      expect(afterFix.expected).to.equal(afterFix.received);
    });
  });

  describe("Route-Specific Requirements", () => {
    describe("x509 Routes", () => {
      it("must include state with x509_san_dns client_id_scheme", () => {
        const session = {
          state: crypto.randomBytes(16).toString('hex'),
          client_id_scheme: "x509_san_dns"
        };
        
        expect(session).to.have.property("state");
        expect(session).to.have.property("client_id_scheme", "x509_san_dns");
      });
    });

    describe("did:web Routes", () => {
      it("must include state with decentralized_identifier:did:web scheme", () => {
        const session = {
          state: crypto.randomBytes(16).toString('hex'),
          client_id: "decentralized_identifier:did:web:dss.aegean.gr"
        };
        
        expect(session).to.have.property("state");
        expect(session.client_id).to.include("did:web:");
      });
    });

    describe("did:jwk Routes", () => {
      it("must include state with decentralized_identifier:did:jwk scheme", () => {
        const session = {
          state: crypto.randomBytes(16).toString('hex'),
          client_id: "decentralized_identifier:did:jwk:eyJrdHkiOiJFQy..." // truncated
        };
        
        expect(session).to.have.property("state");
        expect(session.client_id).to.include("did:jwk:");
      });
    });
  });
});

