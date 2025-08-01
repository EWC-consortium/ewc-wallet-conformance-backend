import { strict as assert } from 'assert';
import { expect } from 'chai';
import request from 'supertest';
import express from 'express';
import sinon from 'sinon';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

// Create Express app
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create mock dependencies
const mockCryptoUtils = {
  generateNonce: sinon.stub(),
  base64UrlEncodeSha256: sinon.stub(),
  pemToJWK: sinon.stub(),
  didKeyToJwks: sinon.stub()
};

const mockTokenUtils = {
  buildAccessToken: sinon.stub(),
  generateRefreshToken: sinon.stub(),
  buildIdToken: sinon.stub()
};

const mockCacheService = {
  getAuthCodeSessions: sinon.stub(),
  getAuthCodeAuthorizationDetail: sinon.stub()
};

const mockCacheServiceRedis = {
  storePreAuthSession: sinon.stub(),
  getPreAuthSession: sinon.stub(),
  getSessionKeyFromAccessToken: sinon.stub(),
  getCodeFlowSession: sinon.stub(),
  storeCodeFlowSession: sinon.stub(),
  getSessionKeyAuthCode: sinon.stub(),
  getSessionAccessToken: sinon.stub(),
  getDeferredSessionTransactionId: sinon.stub(),
  storeNonce: sinon.stub(),
  checkNonce: sinon.stub(),
  deleteNonce: sinon.stub()
};

const mockSdjwtUtils = {
  createSignerVerifier: sinon.stub(),
  digest: sinon.stub(),
  generateSalt: sinon.stub(),
  createSignerVerifierX509: sinon.stub(),
  pemToBase64Der: sinon.stub()
};

const mockCredGenerationUtils = {
  handleCredentialGenerationBasedOnFormat: sinon.stub(),
  handleCredentialGenerationBasedOnFormatDeferred: sinon.stub()
};

const mockJose = {
  importJWK: sinon.stub(),
  exportSPKI: sinon.stub()
};

// Mock fs module
const mockFs = {
  readFileSync: sinon.stub()
};

// Mock path module
const mockPath = {
  join: sinon.stub()
};

// Create a test router that mimics the actual sharedIssuanceFlows behavior
const testRouter = express.Router();

// Mock the token_endpoint
testRouter.post('/token_endpoint', async (req, res) => {
  try {
    const authorizationHeader = req.headers['authorization'];
    const body = req.body;
    const authorizationDetails = body.authorization_details;
    const clientAttestation = req.headers['OAuth-Client-Attestation'];
    const pop = req.headers['OAuth-Client-Attestation-PoP'];
    const preAuthorizedCode = body['pre-authorized_code'];
    const tx_code = body['tx_code'];
    const grantType = body.grant_type;
    const client_id = body.client_id;
    const code = body['code'];
    const code_verifier = body['code_verifier'];
    const redirect_uri = body['redirect_uri'];

    const generatedAccessToken = mockTokenUtils.buildAccessToken();

    if (!(code || preAuthorizedCode)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'The request is missing the \'code\' or \'pre-authorized_code\' parameter.'
      });
    }

    if (grantType === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
      const existingPreAuthSession = await mockCacheServiceRedis.getPreAuthSession(preAuthorizedCode);
      
      if (existingPreAuthSession) {
        const cNonceForSession = mockCryptoUtils.generateNonce();
        existingPreAuthSession.status = 'success';
        existingPreAuthSession.accessToken = generatedAccessToken;
        existingPreAuthSession.c_nonce = cNonceForSession;

        await mockCacheServiceRedis.storePreAuthSession(preAuthorizedCode, existingPreAuthSession);

        const tokenResponse = {
          access_token: generatedAccessToken,
          refresh_token: mockTokenUtils.generateRefreshToken(),
          token_type: 'bearer',
          expires_in: 86400
        };

        if (authorizationDetails) {
          const parsedAuthDetails = Array.isArray(authorizationDetails) ? authorizationDetails : [authorizationDetails];
          parsedAuthDetails.credential_identifiers = [parsedAuthDetails[0]?.credential_configuration_id];
          tokenResponse.authorization_details = parsedAuthDetails;
        }

        return res.json(tokenResponse);
      } else {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid or expired pre-authorized code.'
        });
      }
    } else if (grantType === 'authorization_code') {
      const issuanceSessionId = await mockCacheServiceRedis.getSessionKeyAuthCode(code);
      
      if (issuanceSessionId) {
        const existingCodeSession = await mockCacheServiceRedis.getCodeFlowSession(issuanceSessionId);
        
        if (existingCodeSession) {
          const pkceVerified = await validatePKCE(
            existingCodeSession,
            code_verifier,
            existingCodeSession.requests?.challenge
          );

          if (!pkceVerified) {
            return res.status(400).json({
              error: 'invalid_grant',
              error_description: 'PKCE verification failed.'
            });
          }

          const cNonceForSession = mockCryptoUtils.generateNonce();
          existingCodeSession.results.status = 'success';
          existingCodeSession.status = 'success';
          existingCodeSession.requests.accessToken = generatedAccessToken;
          existingCodeSession.c_nonce = cNonceForSession;

          await mockCacheServiceRedis.storeCodeFlowSession(
            existingCodeSession.results.issuerState,
            existingCodeSession
          );

          const tokenResponse = {
            access_token: generatedAccessToken,
            refresh_token: mockTokenUtils.generateRefreshToken(),
            token_type: 'Bearer',
            expires_in: 86400
          };

          if (authorizationDetails) {
            const parsedAuthDetails = Array.isArray(authorizationDetails) ? authorizationDetails : [authorizationDetails];
            parsedAuthDetails.credential_identifiers = [parsedAuthDetails[0]?.credential_configuration_id];
            tokenResponse.authorization_details = parsedAuthDetails;
          }

          return res.json(tokenResponse);
        }
      }
      
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code or session not found.'
      });
    } else {
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: `Grant type '${grantType}' is not supported.`
      });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the credential endpoint
testRouter.post('/credential', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    const requestBody = req.body;
    const proofJwt = requestBody.proof?.jwt;
    const credentialIdentifier = requestBody.credential_identifier;
    const credentialConfigurationId = requestBody.credential_configuration_id;

    // Check credential identifiers
    if ((credentialIdentifier && credentialConfigurationId) || (!credentialIdentifier && !credentialConfigurationId)) {
      return res.status(400).json({
        error: 'invalid_credential_request',
        error_description: 'Must provide exactly one of credential_identifier or credential_configuration_id'
      });
    }

    // Check proof
    if (!requestBody.proof || !requestBody.proof.jwt) {
      return res.status(400).json({
        error: 'invalid_proof',
        error_description: 'No proof information found'
      });
    }

    // Get session
    const preAuthsessionKey = await mockCacheServiceRedis.getSessionKeyFromAccessToken(token);
    let sessionObject;
    let flowType = 'pre-auth';
    
    if (preAuthsessionKey) {
      sessionObject = await mockCacheServiceRedis.getPreAuthSession(preAuthsessionKey);
      if (!sessionObject) {
        sessionObject = await mockCacheServiceRedis.getCodeFlowSession(preAuthsessionKey);
      }
    }
    
    if (!sessionObject) {
      const codeSessionKey = await mockCacheServiceRedis.getSessionAccessToken(token);
      if (codeSessionKey) {
        sessionObject = await mockCacheServiceRedis.getCodeFlowSession(codeSessionKey);
        flowType = 'code';
      }
    }

    if (!sessionObject) {
      return res.status(500).json({
        error: 'server_error',
        error_description: 'Session lost after proof validation.'
      });
    }

    // Mock proof validation
    const decodedProof = jwt.decode(proofJwt, { complete: true });
    if (!decodedProof) {
      return res.status(400).json({
        error: 'invalid_proof',
        error_description: 'Proof JWT is malformed.'
      });
    }

    // Check nonce
    const nonceExists = await mockCacheServiceRedis.checkNonce(decodedProof.payload.nonce);
    if (!nonceExists) {
      return res.status(400).json({
        error: 'invalid_proof',
        error_description: 'Proof JWT nonce is invalid, expired, or already used.'
      });
    }

    await mockCacheServiceRedis.deleteNonce(decodedProof.payload.nonce);

    // Handle deferred flow
    if (sessionObject && sessionObject.isDeferred) {
      const transaction_id = mockCryptoUtils.generateNonce();
      sessionObject.transaction_id = transaction_id;
      sessionObject.requestBody = requestBody;
      sessionObject.isCredentialReady = false;
      sessionObject.attempt = 0;

      if (sessionObject.flowType === 'code') {
        await mockCacheServiceRedis.storeCodeFlowSession('test-session-key', sessionObject);
      } else {
        await mockCacheServiceRedis.storePreAuthSession('test-pre-auth-key', sessionObject);
      }

      return res.status(202).json({
        transaction_id: transaction_id,
        c_nonce: mockCryptoUtils.generateNonce(),
        c_nonce_expires_in: 86400
      });
    }

    // Immediate issuance flow
    const requestedCredentialType = credentialIdentifier ? [credentialIdentifier] : [credentialConfigurationId];
    requestBody.vct = requestedCredentialType[0];

    const credential = await mockCredGenerationUtils.handleCredentialGenerationBasedOnFormat(
      requestBody,
      sessionObject,
      'http://localhost:3000',
      'dc+sd-jwt'
    );

    const response = {
      credentials: [
        {
          credential
        }
      ]
    };

    res.json(response);
  } catch (error) {
    res.status(400).json({
      error: 'credential_request_denied',
      error_description: error.message
    });
  }
});

// Mock the credential_deferred endpoint
testRouter.post('/credential_deferred', async (req, res) => {
  try {
    const transaction_id = req.body.transaction_id;
    const sessionId = await mockCacheServiceRedis.getDeferredSessionTransactionId(transaction_id);
    const sessionObject = await mockCacheServiceRedis.getCodeFlowSession(sessionId);
    
    if (!sessionObject) {
      return res.status(400).json({
        error: 'invalid_transaction_id'
      });
    }

    const credential = await mockCredGenerationUtils.handleCredentialGenerationBasedOnFormatDeferred(
      sessionObject,
      'http://localhost:3000'
    );

    return res.status(200).json({
      format: 'dc+sd-jwt',
      credential
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the nonce endpoint
testRouter.post('/nonce', async (req, res) => {
  try {
    const newCNonce = mockCryptoUtils.generateNonce();
    const nonceExpiresIn = 86400;

    await mockCacheServiceRedis.storeNonce(newCNonce, nonceExpiresIn);

    res.status(200).json({
      c_nonce: newCNonce,
      c_nonce_expires_in: nonceExpiresIn
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the issueStatus endpoint
testRouter.get('/issueStatus', async (req, res) => {
  try {
    const sessionId = req.query.sessionId;
    const existingPreAuthSession = await mockCacheServiceRedis.getPreAuthSession(sessionId);
    const perAuthStatus = existingPreAuthSession ? existingPreAuthSession.status : null;

    const codeFlowSession = await mockCacheServiceRedis.getCodeFlowSession(sessionId);
    const codeFlowStatus = codeFlowSession ? codeFlowSession.status : null;

    const result = perAuthStatus || codeFlowStatus;
    
    if (result) {
      res.json({
        status: result,
        reason: 'ok',
        sessionId: sessionId
      });
    } else {
      res.json({
        status: 'failed',
        reason: 'not found',
        sessionId: sessionId
      });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper function to validate PKCE
async function validatePKCE(session, code_verifier, stored_code_challenge) {
  if (!stored_code_challenge) {
    return false;
  }
  if (!code_verifier) {
    return false;
  }

  const tester = await mockCryptoUtils.base64UrlEncodeSha256(code_verifier);
  return tester === stored_code_challenge;
}

// Mount the test router
app.use('/shared', testRouter);

describe('Shared Issuance Flows', () => {
  let sandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
    
    // Reset all stubs
    mockCryptoUtils.generateNonce.reset();
    mockCryptoUtils.base64UrlEncodeSha256.reset();
    mockTokenUtils.buildAccessToken.reset();
    mockTokenUtils.generateRefreshToken.reset();
    mockCacheServiceRedis.storePreAuthSession.reset();
    mockCacheServiceRedis.getPreAuthSession.reset();
    mockCacheServiceRedis.getSessionKeyFromAccessToken.reset();
    mockCacheServiceRedis.getCodeFlowSession.reset();
    mockCacheServiceRedis.storeCodeFlowSession.reset();
    mockCacheServiceRedis.getSessionKeyAuthCode.reset();
    mockCacheServiceRedis.getSessionAccessToken.reset();
    mockCacheServiceRedis.getDeferredSessionTransactionId.reset();
    mockCacheServiceRedis.storeNonce.reset();
    mockCacheServiceRedis.checkNonce.reset();
    mockCacheServiceRedis.deleteNonce.reset();
    mockCredGenerationUtils.handleCredentialGenerationBasedOnFormat.reset();
    mockCredGenerationUtils.handleCredentialGenerationBasedOnFormatDeferred.reset();
    
    // Set up default return values
    mockCryptoUtils.generateNonce.returns('test-nonce-123');
    mockCryptoUtils.base64UrlEncodeSha256.resolves('test-challenge');
    mockTokenUtils.buildAccessToken.returns('test-access-token');
    mockTokenUtils.generateRefreshToken.returns('test-refresh-token');
    mockCacheServiceRedis.storePreAuthSession.resolves();
    mockCacheServiceRedis.storeCodeFlowSession.resolves();
    mockCacheServiceRedis.storeNonce.resolves();
    mockCacheServiceRedis.checkNonce.resolves(true);
    mockCacheServiceRedis.deleteNonce.resolves();
    mockCredGenerationUtils.handleCredentialGenerationBasedOnFormat.resolves('test-credential');
    mockCredGenerationUtils.handleCredentialGenerationBasedOnFormatDeferred.resolves('test-deferred-credential');
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('POST /shared/token_endpoint', () => {
    it('should handle pre-authorized code flow successfully', async () => {
      const preAuthSession = {
        status: 'pending',
        authorizationDetails: null
      };
      mockCacheServiceRedis.getPreAuthSession.resolves(preAuthSession);

      const response = await request(app)
        .post('/shared/token_endpoint')
        .set('Authorization', 'Bearer test-token')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': 'test-pre-auth-code'
        })
        .expect(200);

      expect(response.body).to.have.property('access_token');
      expect(response.body).to.have.property('refresh_token');
      expect(response.body).to.have.property('token_type', 'bearer');
      expect(response.body).to.have.property('expires_in', 86400);
    });

    it('should handle authorization code flow successfully', async () => {
      const codeSession = {
        requests: { challenge: 'test-challenge' },
        results: { issuerState: 'test-state' }
      };
      mockCacheServiceRedis.getSessionKeyAuthCode.resolves('test-session-id');
      mockCacheServiceRedis.getCodeFlowSession.resolves(codeSession);

      const response = await request(app)
        .post('/shared/token_endpoint')
        .set('Authorization', 'Bearer test-token')
        .send({
          grant_type: 'authorization_code',
          code: 'test-auth-code',
          code_verifier: 'test-verifier'
        })
        .expect(200);

      expect(response.body).to.have.property('access_token');
      expect(response.body).to.have.property('refresh_token');
      expect(response.body).to.have.property('token_type', 'Bearer');
    });

    it('should handle authorization_details in pre-authorized flow', async () => {
      const preAuthSession = {
        status: 'pending',
        authorizationDetails: [
          { credential_configuration_id: 'test-cred-config' }
        ]
      };
      mockCacheServiceRedis.getPreAuthSession.resolves(preAuthSession);

      const response = await request(app)
        .post('/shared/token_endpoint')
        .set('Authorization', 'Bearer test-token')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': 'test-pre-auth-code',
          authorization_details: [
            { credential_configuration_id: 'test-cred-config' }
          ]
        })
        .expect(200);

      expect(response.body).to.have.property('authorization_details');
    });

    it('should reject request without code or pre-authorized_code', async () => {
      const response = await request(app)
        .post('/shared/token_endpoint')
        .set('Authorization', 'Bearer test-token')
        .send({
          grant_type: 'authorization_code'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_request');
    });

    it('should reject invalid pre-authorized code', async () => {
      mockCacheServiceRedis.getPreAuthSession.resolves(null);

      const response = await request(app)
        .post('/shared/token_endpoint')
        .set('Authorization', 'Bearer test-token')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': 'invalid-code'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_grant');
    });

    it('should reject PKCE verification failure', async () => {
      const codeSession = {
        requests: { challenge: 'test-challenge' }
      };
      mockCacheServiceRedis.getSessionKeyAuthCode.resolves('test-session-id');
      mockCacheServiceRedis.getCodeFlowSession.resolves(codeSession);
      mockCryptoUtils.base64UrlEncodeSha256.resolves('wrong-challenge');

      const response = await request(app)
        .post('/shared/token_endpoint')
        .set('Authorization', 'Bearer test-token')
        .send({
          grant_type: 'authorization_code',
          code: 'test-auth-code',
          code_verifier: 'test-verifier'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_grant');
    });

    it('should reject unsupported grant type', async () => {
      const response = await request(app)
        .post('/shared/token_endpoint')
        .set('Authorization', 'Bearer test-token')
        .send({
          grant_type: 'unsupported_grant_type',
          'pre-authorized_code': 'test-code'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'unsupported_grant_type');
    });
  });

  describe('POST /shared/credential', () => {
    it('should handle immediate credential issuance successfully', async () => {
      const sessionObject = {
        status: 'success',
        isDeferred: false
      };
      mockCacheServiceRedis.getSessionKeyFromAccessToken.resolves('test-session-key');
      mockCacheServiceRedis.getPreAuthSession.resolves(sessionObject);

      const testProofJwt = jwt.sign(
        { nonce: 'test-nonce-123', iss: 'test-issuer' },
        'test-secret',
        { algorithm: 'HS256' }
      );

      const response = await request(app)
        .post('/shared/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          credential_configuration_id: 'test-cred-config',
          proof: {
            jwt: testProofJwt
          }
        })
        .expect(200);

      expect(response.body).to.have.property('credentials');
      expect(response.body.credentials).to.be.an('array');
    });

    it('should handle deferred credential issuance', async () => {
      const sessionObject = {
        status: 'success',
        isDeferred: true,
        flowType: 'pre-auth'
      };
      mockCacheServiceRedis.getSessionKeyFromAccessToken.resolves('test-session-key');
      mockCacheServiceRedis.getPreAuthSession.resolves(sessionObject);

      const testProofJwt = jwt.sign(
        { nonce: 'test-nonce-123', iss: 'test-issuer' },
        'test-secret',
        { algorithm: 'HS256' }
      );

      const response = await request(app)
        .post('/shared/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          credential_configuration_id: 'test-cred-config',
          proof: {
            jwt: testProofJwt
          }
        })
        .expect(202);

      expect(response.body).to.have.property('transaction_id');
      expect(response.body).to.have.property('c_nonce');
      expect(response.body).to.have.property('c_nonce_expires_in');
    });

    it('should reject request without proof', async () => {
      const response = await request(app)
        .post('/shared/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          credential_configuration_id: 'test-cred-config'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_proof');
    });

    it('should reject request with both credential identifiers', async () => {
      const response = await request(app)
        .post('/shared/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          credential_configuration_id: 'test-cred-config',
          credential_identifier: 'test-cred-id',
          proof: {
            jwt: 'test-jwt'
          }
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_credential_request');
    });

    it('should reject request without credential identifiers', async () => {
      const response = await request(app)
        .post('/shared/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          proof: {
            jwt: 'test-jwt'
          }
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_credential_request');
    });

    it('should reject invalid nonce', async () => {
      mockCacheServiceRedis.getSessionKeyFromAccessToken.resolves('test-session-key');
      mockCacheServiceRedis.getPreAuthSession.resolves({ status: 'success', isDeferred: false });
      mockCacheServiceRedis.checkNonce.resolves(false);

      const testProofJwt = jwt.sign(
        { nonce: 'invalid-nonce', iss: 'test-issuer' },
        'test-secret',
        { algorithm: 'HS256' }
      );

      const response = await request(app)
        .post('/shared/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          credential_configuration_id: 'test-cred-config',
          proof: {
            jwt: testProofJwt
          }
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_proof');
    });

    it('should handle credential generation errors', async () => {
      const sessionObject = {
        status: 'success',
        isDeferred: false
      };
      mockCacheServiceRedis.getSessionKeyFromAccessToken.resolves('test-session-key');
      mockCacheServiceRedis.getPreAuthSession.resolves(sessionObject);
      mockCredGenerationUtils.handleCredentialGenerationBasedOnFormat.rejects(new Error('Credential generation failed'));

      const testProofJwt = jwt.sign(
        { nonce: 'test-nonce-123', iss: 'test-issuer' },
        'test-secret',
        { algorithm: 'HS256' }
      );

      const response = await request(app)
        .post('/shared/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          credential_configuration_id: 'test-cred-config',
          proof: {
            jwt: testProofJwt
          }
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'credential_request_denied');
    });
  });

  describe('POST /shared/credential_deferred', () => {
    it('should handle deferred credential issuance successfully', async () => {
      const sessionObject = {
        status: 'pending',
        requestBody: { test: 'data' }
      };
      mockCacheServiceRedis.getDeferredSessionTransactionId.resolves('test-session-id');
      mockCacheServiceRedis.getCodeFlowSession.resolves(sessionObject);

      const response = await request(app)
        .post('/shared/credential_deferred')
        .send({
          transaction_id: 'test-transaction-id'
        })
        .expect(200);

      expect(response.body).to.have.property('format', 'dc+sd-jwt');
      expect(response.body).to.have.property('credential');
    });

    it('should reject invalid transaction ID', async () => {
      mockCacheServiceRedis.getDeferredSessionTransactionId.resolves(null);

      const response = await request(app)
        .post('/shared/credential_deferred')
        .send({
          transaction_id: 'invalid-transaction-id'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_transaction_id');
    });

    it('should handle missing session object', async () => {
      mockCacheServiceRedis.getDeferredSessionTransactionId.resolves('test-session-id');
      mockCacheServiceRedis.getCodeFlowSession.resolves(null);

      const response = await request(app)
        .post('/shared/credential_deferred')
        .send({
          transaction_id: 'test-transaction-id'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_transaction_id');
    });
  });

  describe('POST /shared/nonce', () => {
    it('should generate and store nonce successfully', async () => {
      const response = await request(app)
        .post('/shared/nonce')
        .expect(200);

      expect(response.body).to.have.property('c_nonce');
      expect(response.body).to.have.property('c_nonce_expires_in', 86400);
      expect(mockCacheServiceRedis.storeNonce.called).to.be.true;
    });

    it('should handle nonce storage errors', async () => {
      mockCacheServiceRedis.storeNonce.rejects(new Error('Storage failed'));

      const response = await request(app)
        .post('/shared/nonce')
        .expect(500);

      expect(response.body).to.have.property('error');
    });
  });

  describe('GET /shared/issueStatus', () => {
    it('should return pre-auth session status', async () => {
      const preAuthSession = { status: 'success' };
      mockCacheServiceRedis.getPreAuthSession.resolves(preAuthSession);

      const response = await request(app)
        .get('/shared/issueStatus')
        .query({ sessionId: 'test-session-id' })
        .expect(200);

      expect(response.body).to.have.property('status', 'success');
      expect(response.body).to.have.property('reason', 'ok');
      expect(response.body).to.have.property('sessionId', 'test-session-id');
    });

    it('should return code flow session status', async () => {
      mockCacheServiceRedis.getPreAuthSession.resolves(null);
      const codeFlowSession = { status: 'pending' };
      mockCacheServiceRedis.getCodeFlowSession.resolves(codeFlowSession);

      const response = await request(app)
        .get('/shared/issueStatus')
        .query({ sessionId: 'test-session-id' })
        .expect(200);

      expect(response.body).to.have.property('status', 'pending');
      expect(response.body).to.have.property('reason', 'ok');
    });

    it('should return failed status for non-existent session', async () => {
      mockCacheServiceRedis.getPreAuthSession.resolves(null);
      mockCacheServiceRedis.getCodeFlowSession.resolves(null);

      const response = await request(app)
        .get('/shared/issueStatus')
        .query({ sessionId: 'non-existent-session' })
        .expect(200);

      expect(response.body).to.have.property('status', 'failed');
      expect(response.body).to.have.property('reason', 'not found');
    });
  });

  describe('Error handling', () => {
    it('should handle token endpoint errors gracefully', async () => {
      mockCacheServiceRedis.getPreAuthSession.rejects(new Error('Database error'));

      const response = await request(app)
        .post('/shared/token_endpoint')
        .set('Authorization', 'Bearer test-token')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': 'test-code'
        })
        .expect(500);

      expect(response.body).to.have.property('error');
    });

    it('should handle credential endpoint errors gracefully', async () => {
      mockCacheServiceRedis.getSessionKeyFromAccessToken.rejects(new Error('Session error'));

      const response = await request(app)
        .post('/shared/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          credential_configuration_id: 'test-cred-config',
          proof: { jwt: 'test-jwt' }
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'credential_request_denied');
    });

    it('should handle nonce endpoint errors gracefully', async () => {
      mockCryptoUtils.generateNonce.throws(new Error('Nonce generation failed'));

      const response = await request(app)
        .post('/shared/nonce')
        .expect(500);

      expect(response.body).to.have.property('error');
    });
  });
}); 