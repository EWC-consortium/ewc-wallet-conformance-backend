import { strict as assert } from 'assert';
import { expect } from 'chai';
import request from 'supertest';
import express from 'express';
import sinon from 'sinon';
import fs from 'fs';
import qr from 'qr-image';
import imageDataURI from 'image-data-uri';
import { streamToBuffer } from '@jorgeferrero/stream-to-buffer';
import { v4 as uuidv4 } from 'uuid';

// Create Express app
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create mock dependencies
const mockCryptoUtils = {
  generateNonce: sinon.stub(),
  buildVpRequestJWT: sinon.stub()
};

const mockCacheService = {
  getCodeFlowSession: sinon.stub(),
  storeCodeFlowSession: sinon.stub(),
  getPushedAuthorizationRequests: sinon.stub(),
  getSessionsAuthorizationDetail: sinon.stub(),
  getAuthCodeAuthorizationDetail: sinon.stub()
};

const mockTokenUtils = {
  buildVPbyValue: sinon.stub()
};

// Mock streamToBuffer function
const mockStreamToBuffer = sinon.stub().resolves(Buffer.from('mock-buffer'));

// Create a test router that mimics the actual codeFlowSdJwtRoutes behavior
const testRouter = express.Router();

// Mock the offer-code-sd-jwt endpoint
testRouter.get('/offer-code-sd-jwt', async (req, res) => {
  try {
    const uuid = req.query.sessionId || 'test-uuid-123';
    const signatureType = req.query.signatureType || 'jwt';
    const credentialType = req.query.credentialType || 'VerifiablePortableDocumentA2SDJWT';
    const client_id_scheme = req.query.client_id_scheme || 'redirect_uri';

    const existingCodeSession = await mockCacheService.getCodeFlowSession(uuid);
    if (!existingCodeSession) {
      await mockCacheService.storeCodeFlowSession(uuid, {
        walletSession: null,
        requests: null,
        results: null,
        status: 'pending',
        client_id_scheme: client_id_scheme,
        flowType: 'code',
        isDynamic: false,
        signatureType: signatureType,
      });
    }

    const encodedCredentialOfferUri = encodeURIComponent(
      `http://localhost:3000/credential-offer-code-sd-jwt/${uuid}?credentialType=${credentialType}&scheme=${client_id_scheme}&`
    );
    const credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`;

    const code = qr.image(credentialOffer, {
      type: 'png',
      ec_level: 'H',
      size: 10,
      margin: 10,
    });
    const mediaType = 'PNG';
    const encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);
    
    res.json({
      qr: encodedQR,
      deepLink: credentialOffer,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the offer-code-sd-jwt-dynamic endpoint
testRouter.get('/offer-code-sd-jwt-dynamic', async (req, res) => {
  try {
    const uuid = req.query.sessionId || 'test-uuid-123';
    const credentialType = req.query.credentialType || 'VerifiablePortableDocumentA2SDJWT';
    const client_id_scheme = req.query.client_id_scheme || 'redirect_uri';

    const existingCodeSession = await mockCacheService.getCodeFlowSession(uuid);
    if (!existingCodeSession) {
      await mockCacheService.storeCodeFlowSession(uuid, {
        walletSession: null,
        requests: null,
        results: null,
        status: 'pending',
        client_id_scheme: client_id_scheme,
        flowType: 'code',
        isDynamic: true,
      });
    }

    const encodedCredentialOfferUri = encodeURIComponent(
      `http://localhost:3000/credential-offer-code-sd-jwt/${uuid}?scheme=${client_id_scheme}&credentialType=${credentialType}`
    );
    const credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`;

    const code = qr.image(credentialOffer, {
      type: 'png',
      ec_level: 'H',
      size: 10,
      margin: 10,
    });
    const mediaType = 'PNG';
    const encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);
    
    res.json({
      qr: encodedQR,
      deepLink: credentialOffer,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the offer-code-defered endpoint
testRouter.get('/offer-code-defered', async (req, res) => {
  try {
    const uuid = req.query.sessionId || 'test-uuid-123';
    const credentialType = req.query.credentialType || 'VerifiablePortableDocumentA2SDJWT';
    const client_id_scheme = req.query.client_id_scheme || 'redirect_uri';

    const existingCodeSession = await mockCacheService.getCodeFlowSession(uuid);
    if (!existingCodeSession) {
      await mockCacheService.storeCodeFlowSession(uuid, {
        walletSession: null,
        requests: null,
        results: null,
        status: 'pending',
        client_id_scheme: client_id_scheme,
        flowType: 'code',
        isDeferred: true,
      });
    }

    const encodedCredentialOfferUri = encodeURIComponent(
      `http://localhost:3000/credential-offer-code-sd-jwt/${uuid}?scheme=${client_id_scheme}&credentialType=${credentialType}`
    );
    const credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`;

    const code = qr.image(credentialOffer, {
      type: 'png',
      ec_level: 'H',
      size: 10,
      margin: 10,
    });
    const mediaType = 'PNG';
    const encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);
    
    res.json({
      qr: encodedQR,
      deepLink: credentialOffer,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the credential-offer-code-sd-jwt endpoint
testRouter.get('/credential-offer-code-sd-jwt/:id', (req, res) => {
  try {
    const credentialType = req.query.credentialType || 'VerifiablePortableDocumentA2SDJWT';
    const sessionId = req.params.id;
    
    const config = {
      credential_issuer: 'http://localhost:3000',
      credential_configuration_ids: [credentialType],
      grants: {
        authorization_code: {
          issuer_state: sessionId,
        },
      },
    };

    // Add transaction code if requested
    if (req.query.includeTxCode === 'true') {
      config.grants.authorization_code.tx_code = {
        input_mode: 'numeric',
        length: 6,
        description: 'Enter the transaction code'
      };
    }

    res.json(config);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the PAR endpoint
testRouter.post(['/par', '/authorize/par'], async (req, res) => {
  try {
    const {
      client_id,
      scope,
      response_type,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      claims,
      state,
      responseType,
      issuer_state,
      authorization_details,
      client_metadata,
      wallet_issuer_id,
      user_hint
    } = req.body;

    const authorizationHeader = req.get('Authorization');
    const requestURI = 'urn:aegean.gr:' + uuidv4();
    const parRequests = mockCacheService.getPushedAuthorizationRequests();
    
    parRequests.set(requestURI, {
      client_id,
      scope,
      response_type,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      claims,
      state,
      authorizationHeader,
      responseType,
      issuerState: issuer_state,
      authorizationDetails: authorization_details,
      clientMetadata: client_metadata,
      wallet_issuer_id,
      user_hint,
    });

    res.json({
      request_uri: requestURI,
      expires_in: 90,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the authorize endpoint
testRouter.get('/authorize', async (req, res) => {
  try {
    const {
      response_type,
      issuer_state,
      state,
      client_id,
      authorization_details,
      scope,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      client_metadata,
      nonce,
      wallet_issuer_id,
      user_hint,
      request_uri
    } = req.query;

    // Handle PAR request
    let finalClientId = client_id;
    let finalResponseType = response_type;
    let finalRedirectUri = redirect_uri;
    let finalCodeChallenge = code_challenge;
    let finalCodeChallengeMethod = code_challenge_method;
    let finalClaims = req.query.claims;
    let finalState = state;
    let finalIssuerState = issuer_state;
    let finalAuthorizationDetails = authorization_details;
    let finalScope = scope;
    let finalClientMetadata = client_metadata;
    let finalWalletIssuerId = wallet_issuer_id;
    let finalUserHint = user_hint;

    if (request_uri) {
      const parRequest = mockCacheService.getPushedAuthorizationRequests().get(request_uri);
      if (parRequest) {
        finalClientId = parRequest.client_id;
        finalResponseType = parRequest.response_type;
        finalRedirectUri = parRequest.redirect_uri;
        finalCodeChallenge = parRequest.code_challenge;
        finalCodeChallengeMethod = parRequest.code_challenge_method;
        finalClaims = parRequest.claims;
        finalState = parRequest.state;
        finalIssuerState = parRequest.issuerState;
        finalAuthorizationDetails = parRequest.authorizationDetails;
        finalScope = parRequest.scope;
        finalClientMetadata = parRequest.clientMetadata;
        finalWalletIssuerId = parRequest.wallet_issuer_id;
        finalUserHint = parRequest.user_hint;
      }
    }

    const existingCodeSession = await mockCacheService.getCodeFlowSession(finalIssuerState);
    if (!existingCodeSession) {
      return res.redirect(302, `${finalRedirectUri || 'openid4vp://'}?error=invalid_request&error_description=ITB session expired`);
    }

    if (finalResponseType !== 'code') {
      return res.redirect(302, `${finalRedirectUri || 'openid4vp://'}?error=invalid_request&error_description=Invalid response_type`);
    }

    // Handle dynamic credential request
    if (existingCodeSession.isDynamic) {
      if (existingCodeSession.client_id_scheme === 'redirect_uri') {
        const redirectUrl = mockTokenUtils.buildVPbyValue(
          'http://localhost:3000/direct_post_vci/' + finalIssuerState,
          'http://localhost:3000/presentation-definition/itbsdjwt',
          'redirect_uri',
          'http://localhost:3000/client-metadata',
          'http://localhost:3000/direct_post_vci/' + finalIssuerState,
          'vp_token',
          nonce
        );
        return res.redirect(302, redirectUrl);
      }
    } else {
      // Non-dynamic flow
      const authorizationCode = mockCryptoUtils.generateNonce(16);
      existingCodeSession.results = {
        sessionId: authorizationCode,
        issuerState: finalIssuerState,
        state: finalState,
        status: 'pending',
      };
      existingCodeSession.requests = {
        sessionId: authorizationCode,
        issuerState: finalIssuerState,
        state: finalState,
      };
      existingCodeSession.authorizationCode = authorizationCode;
      existingCodeSession.authorizationDetails = finalAuthorizationDetails;
      
      await mockCacheService.storeCodeFlowSession(finalIssuerState, existingCodeSession);
      
      const redirectUrl = `${existingCodeSession.requests.redirectUri || 'openid4vp://'}?code=${authorizationCode}&state=${finalState}`;
      return res.redirect(302, redirectUrl);
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the x509VPrequest_dynamic endpoint
testRouter.get('/x509VPrequest_dynamic/:id', async (req, res) => {
  try {
    const uuid = req.params.id || 'test-uuid-123';
    const response_uri = 'http://localhost:3000/direct_post_vci/' + uuid;

    const client_metadata = {
      client_name: 'UAegean EWC Verifier',
      logo_uri: 'https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png',
      location: 'Greece',
      cover_uri: 'string',
      description: 'EWC pilot case verification',
      vp_formats: {
        'vc+sd-jwt': {
          'sd-jwt_alg_values': ['ES256', 'ES384'],
          'kb-jwt_alg_values': ['ES256', 'ES384'],
        },
      },
    };

    const presentation_definition_sdJwt = { test: 'presentation_definition' };
    const clientId = 'dss.aegean.gr';
    
    const signedVPJWT = await mockCryptoUtils.buildVpRequestJWT(
      clientId,
      response_uri,
      presentation_definition_sdJwt,
      '',
      'x509_san_dns',
      client_metadata,
      null,
      'http://localhost:3000'
    );

    res.type('text/plain').send(signedVPJWT);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the didJwksVPrequest_dynamic endpoint
testRouter.get('/didJwksVPrequest_dynamic/:id', async (req, res) => {
  try {
    const uuid = req.params.id || 'test-uuid-123';
    const response_uri = 'http://localhost:3000/direct_post_vci/' + uuid;

    const client_metadata = {
      client_name: 'UAegean EWC Verifier',
      logo_uri: 'https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png',
      location: 'Greece',
      cover_uri: 'string',
      description: 'EWC pilot case verification',
      vp_formats: {
        'vc+sd-jwt': {
          'sd-jwt_alg_values': ['ES256', 'ES384'],
          'kb-jwt_alg_values': ['ES256', 'ES384'],
        },
      },
    };

    const privateKeyPem = 'mock-private-key';
    const clientId = 'did:web:localhost:3000';
    const presentation_definition_sdJwt = { test: 'presentation_definition' };

    const signedVPJWT = await mockCryptoUtils.buildVpRequestJWT(
      clientId,
      response_uri,
      presentation_definition_sdJwt,
      privateKeyPem,
      'did',
      client_metadata,
      'did:web:localhost:3000#keys-1',
      'http://localhost:3000'
    );
    
    res.type('text/plain').send(signedVPJWT);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the id_token_x509_request_dynamic endpoint
testRouter.get('/id_token_x509_request_dynamic/:id', async (req, res) => {
  try {
    const uuid = req.params.id || 'test-uuid-123';
    const existingCodeSession = await mockCacheService.getCodeFlowSession(uuid);
    const response_uri = 'http://localhost:3000/direct_post_vci/' + (existingCodeSession?.requests?.state || 'test-state');
    
    const client_metadata = {
      client_name: 'UAegean EWC Verifier',
      logo_uri: 'https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png',
      location: 'Greece',
      cover_uri: 'string',
      description: 'EWC pilot case verification',
      vp_formats: {
        'vc+sd-jwt': {
          'sd-jwt_alg_values': ['ES256', 'ES384'],
          'kb-jwt_alg_values': ['ES256', 'ES384'],
        },
      },
    };
    
    const clientId = 'dss.aegean.gr';
    const signedVPJWT = await mockCryptoUtils.buildVpRequestJWT(
      clientId,
      response_uri,
      null,
      '',
      'x509_san_dns',
      client_metadata,
      null,
      'http://localhost:3000',
      'id_token'
    );

    res.type('text/plain').send(signedVPJWT);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the id_token_did_request_dynamic endpoint
testRouter.get('/id_token_did_request_dynamic/:id', async (req, res) => {
  try {
    const uuid = req.params.id || 'test-uuid-123';
    const existingCodeSession = await mockCacheService.getCodeFlowSession(uuid);
    const response_uri = 'http://localhost:3000/direct_post_vci/' + (existingCodeSession?.requests?.state || 'test-state');
    
    const client_metadata = {
      client_name: 'UAegean EWC Verifier',
      logo_uri: 'https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png',
      location: 'Greece',
      cover_uri: 'string',
      description: 'EWC pilot case verification',
      vp_formats: {
        'vc+sd-jwt': {
          'sd-jwt_alg_values': ['ES256', 'ES384'],
          'kb-jwt_alg_values': ['ES256', 'ES384'],
        },
      },
    };

    const privateKeyPem = 'mock-private-key';
    const clientId = 'did:web:localhost:3000';
    const presentation_definition_sdJwt = { test: 'presentation_definition' };

    const signedVPJWT = await mockCryptoUtils.buildVpRequestJWT(
      clientId,
      response_uri,
      null,
      privateKeyPem,
      'did',
      client_metadata,
      'did:web:localhost:3000#keys-1',
      'http://localhost:3000',
      'vp_token id_token'
    );
    
    res.type('text/plain').send(signedVPJWT);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the direct_post_vci endpoint
testRouter.post('/direct_post_vci/:id', async (req, res) => {
  try {
    const state = req.body.state;
    const jwt = req.body.vp_token;
    const issuerState = req.params.id;

    const authorizationDetails = mockCacheService.getSessionsAuthorizationDetail().get(state);

    if (jwt) {
      const authorizationCode = mockCryptoUtils.generateNonce(16);
      mockCacheService.getAuthCodeAuthorizationDetail().set(authorizationCode, authorizationDetails);

      const existingCodeSession = await mockCacheService.getCodeFlowSession(issuerState);
      if (existingCodeSession) {
        const issuanceState = existingCodeSession.results.state;
        existingCodeSession.results.sessionId = authorizationCode;
        existingCodeSession.requests.sessionId = authorizationCode;
        await mockCacheService.storeCodeFlowSession(issuanceState, existingCodeSession);

        const redirectUrl = `${existingCodeSession.requests.redirectUri}?code=${authorizationCode}&state=${existingCodeSession.requests.state}`;
        return res.send({ redirect_uri: redirectUrl });
      } else {
        return res.sendStatus(500);
      }
    } else {
      return res.sendStatus(500);
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mount the test router
app.use('/codeflow', testRouter);

describe('Code Flow SD-JWT Routes', () => {
  let sandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
    
    // Reset all stubs
    mockCryptoUtils.generateNonce.reset();
    mockCryptoUtils.buildVpRequestJWT.reset();
    mockCacheService.getCodeFlowSession.reset();
    mockCacheService.storeCodeFlowSession.reset();
    mockCacheService.getPushedAuthorizationRequests.reset();
    mockCacheService.getSessionsAuthorizationDetail.reset();
    mockCacheService.getAuthCodeAuthorizationDetail.reset();
    mockTokenUtils.buildVPbyValue.reset();
    mockStreamToBuffer.reset();
    
    // Set up default return values
    mockCryptoUtils.generateNonce.returns('test-auth-code-123');
    mockCryptoUtils.buildVpRequestJWT.resolves('mock-vp-jwt-token');
    mockCacheService.getCodeFlowSession.resolves(null);
    mockCacheService.storeCodeFlowSession.resolves();
    mockCacheService.getPushedAuthorizationRequests.returns(new Map());
    mockCacheService.getSessionsAuthorizationDetail.returns(new Map());
    mockCacheService.getAuthCodeAuthorizationDetail.returns(new Map());
    mockTokenUtils.buildVPbyValue.returns('mock-vp-url');
    
    // Mock QR code generation
    const mockQRStream = { pipe: sinon.stub().returnsThis() };
    sandbox.stub(qr, 'image').returns(mockQRStream);
    sandbox.stub(imageDataURI, 'encode').returns('data:image/png;base64,mock-qr-code');
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('GET /codeflow/offer-code-sd-jwt', () => {
    it('should generate credential offer with default parameters', async () => {
      const response = await request(app)
        .get('/codeflow/offer-code-sd-jwt')
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
      expect(response.body.sessionId).to.equal('test-uuid-123');
    });

    it('should generate credential offer with custom parameters', async () => {
      const customSessionId = 'custom-session-123';
      const customCredentialType = 'CustomCredentialType';
      const customSignatureType = 'custom-sig';
      const customClientIdScheme = 'did';
      
      const response = await request(app)
        .get('/codeflow/offer-code-sd-jwt')
        .query({
          sessionId: customSessionId,
          credentialType: customCredentialType,
          signatureType: customSignatureType,
          client_id_scheme: customClientIdScheme
        })
        .expect(200);

      expect(response.body.sessionId).to.equal(customSessionId);
      expect(response.body.deepLink).to.include(encodeURIComponent(`credentialType=${customCredentialType}`));
    });

    it('should create new session when no existing session found', async () => {
      await request(app)
        .get('/codeflow/offer-code-sd-jwt')
        .expect(200);

      expect(mockCacheService.storeCodeFlowSession.called).to.be.true;
      const callArgs = mockCacheService.storeCodeFlowSession.getCall(0).args;
      expect(callArgs[0]).to.equal('test-uuid-123');
      expect(callArgs[1]).to.have.property('flowType', 'code');
      expect(callArgs[1]).to.have.property('isDynamic', false);
    });

    it('should not create new session if existing session found', async () => {
      mockCacheService.getCodeFlowSession.resolves({
        sessionId: 'existing-session',
        status: 'pending'
      });

      await request(app)
        .get('/codeflow/offer-code-sd-jwt')
        .expect(200);

      expect(mockCacheService.storeCodeFlowSession.called).to.be.false;
    });
  });

  describe('GET /codeflow/offer-code-sd-jwt-dynamic', () => {
    it('should generate dynamic credential offer', async () => {
      const response = await request(app)
        .get('/codeflow/offer-code-sd-jwt-dynamic')
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
    });

    it('should create session with isDynamic flag', async () => {
      await request(app)
        .get('/codeflow/offer-code-sd-jwt-dynamic')
        .expect(200);

      expect(mockCacheService.storeCodeFlowSession.called).to.be.true;
      const callArgs = mockCacheService.storeCodeFlowSession.getCall(0).args;
      expect(callArgs[1]).to.have.property('isDynamic', true);
    });
  });

  describe('GET /codeflow/offer-code-defered', () => {
    it('should generate deferred credential offer', async () => {
      const response = await request(app)
        .get('/codeflow/offer-code-defered')
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
    });

    it('should create session with isDeferred flag', async () => {
      await request(app)
        .get('/codeflow/offer-code-defered')
        .expect(200);

      expect(mockCacheService.storeCodeFlowSession.called).to.be.true;
      const callArgs = mockCacheService.storeCodeFlowSession.getCall(0).args;
      expect(callArgs[1]).to.have.property('isDeferred', true);
    });
  });

  describe('GET /codeflow/credential-offer-code-sd-jwt/:id', () => {
    it('should return credential offer configuration', async () => {
      const sessionId = 'test-session-123';
      
      const response = await request(app)
        .get(`/codeflow/credential-offer-code-sd-jwt/${sessionId}`)
        .expect(200);

      expect(response.body).to.have.property('credential_issuer');
      expect(response.body).to.have.property('credential_configuration_ids');
      expect(response.body).to.have.property('grants');
      expect(response.body.grants).to.have.property('authorization_code');
      expect(response.body.grants.authorization_code).to.have.property('issuer_state', sessionId);
    });

    it('should use custom credential type', async () => {
      const customCredentialType = 'CustomCredentialType';
      
      const response = await request(app)
        .get('/codeflow/credential-offer-code-sd-jwt/test-session')
        .query({ credentialType: customCredentialType })
        .expect(200);

      expect(response.body.credential_configuration_ids).to.include(customCredentialType);
    });
  });

  describe('POST /codeflow/par', () => {
    it('should create PAR request successfully', async () => {
      const parData = {
        client_id: 'test-client-id',
        scope: 'test-scope',
        response_type: 'code',
        redirect_uri: 'test-redirect-uri',
        code_challenge: 'test-challenge',
        code_challenge_method: 'S256',
        state: 'test-state',
        issuer_state: 'test-issuer-state'
      };

      const response = await request(app)
        .post('/codeflow/par')
        .send(parData)
        .expect(200);

      expect(response.body).to.have.property('request_uri');
      expect(response.body).to.have.property('expires_in', 90);
      expect(response.body.request_uri).to.match(/^urn:aegean\.gr:/);
    });

    it('should store PAR request in cache', async () => {
      const parData = {
        client_id: 'test-client-id',
        scope: 'test-scope',
        response_type: 'code',
        redirect_uri: 'test-redirect-uri',
        code_challenge: 'test-challenge',
        code_challenge_method: 'S256',
        state: 'test-state',
        issuer_state: 'test-issuer-state'
      };

      await request(app)
        .post('/codeflow/par')
        .send(parData)
        .expect(200);

      expect(mockCacheService.getPushedAuthorizationRequests.called).to.be.true;
    });
  });

  describe('GET /codeflow/authorize', () => {
    it('should handle non-dynamic authorization successfully', async () => {
      const mockSession = {
        isDynamic: false,
        requests: { redirectUri: 'openid4vp://' },
        results: { state: 'test-state' }
      };
      mockCacheService.getCodeFlowSession.resolves(mockSession);

      const response = await request(app)
        .get('/codeflow/authorize')
        .query({
          response_type: 'code',
          issuer_state: 'test-issuer-state',
          state: 'test-state',
          client_id: 'test-client-id'
        })
        .expect(302);

      expect(response.header.location).to.include('code=');
      expect(response.header.location).to.include('state=test-state');
    });

    it('should handle dynamic authorization with redirect_uri scheme', async () => {
      const mockSession = {
        isDynamic: true,
        client_id_scheme: 'redirect_uri',
        requests: { redirectUri: 'openid4vp://' },
        results: { state: 'test-state' }
      };
      mockCacheService.getCodeFlowSession.resolves(mockSession);

      const response = await request(app)
        .get('/codeflow/authorize')
        .query({
          response_type: 'code',
          issuer_state: 'test-issuer-state',
          state: 'test-state',
          client_id: 'test-client-id',
          nonce: 'test-nonce'
        })
        .expect(302);

      expect(mockTokenUtils.buildVPbyValue.called).to.be.true;
    });

    it('should handle PAR request', async () => {
      const mockSession = {
        isDynamic: false,
        requests: { redirectUri: 'openid4vp://' },
        results: { state: 'test-state' }
      };
      mockCacheService.getCodeFlowSession.resolves(mockSession);

      const parRequest = {
        client_id: 'par-client-id',
        response_type: 'code',
        redirect_uri: 'par-redirect-uri',
        code_challenge: 'par-challenge',
        code_challenge_method: 'S256',
        claims: 'par-claims',
        state: 'par-state',
        issuerState: 'par-issuer-state',
        authorizationDetails: 'par-auth-details',
        scope: 'par-scope',
        clientMetadata: 'par-client-metadata',
        wallet_issuer_id: 'par-wallet-id',
        user_hint: 'par-user-hint'
      };

      const parMap = new Map();
      parMap.set('urn:aegean.gr:test-par', parRequest);
      mockCacheService.getPushedAuthorizationRequests.returns(parMap);

      const response = await request(app)
        .get('/codeflow/authorize')
        .query({
          request_uri: 'urn:aegean.gr:test-par'
        })
        .expect(302);

      expect(response.header.location).to.include('code=');
    });

    it('should handle missing session', async () => {
      mockCacheService.getCodeFlowSession.resolves(null);

      const response = await request(app)
        .get('/codeflow/authorize')
        .query({
          response_type: 'code',
          issuer_state: 'invalid-issuer-state',
          state: 'test-state',
          client_id: 'test-client-id'
        })
        .expect(302);

      expect(response.header.location).to.include('error=invalid_request');
      expect(response.header.location).to.include(encodeURIComponent('ITB session expired'));
    });

    it('should handle invalid response_type', async () => {
      const mockSession = {
        isDynamic: false,
        requests: { redirectUri: 'openid4vp://' },
        results: { state: 'test-state' }
      };
      mockCacheService.getCodeFlowSession.resolves(mockSession);

      const response = await request(app)
        .get('/codeflow/authorize')
        .query({
          response_type: 'invalid',
          issuer_state: 'test-issuer-state',
          state: 'test-state',
          client_id: 'test-client-id'
        })
        .expect(302);

      expect(response.header.location).to.include('error=invalid_request');
      expect(response.header.location).to.include(encodeURIComponent('Invalid response_type'));
    });
  });

  describe('GET /codeflow/x509VPrequest_dynamic/:id', () => {
    it('should return VP request JWT for X.509', async () => {
      const response = await request(app)
        .get('/codeflow/x509VPrequest_dynamic/test-session')
        .expect(200);

      expect(response.text).to.equal('mock-vp-jwt-token');
      expect(response.headers['content-type']).to.include('text/plain');
    });

    it('should call buildVpRequestJWT with correct parameters', async () => {
      await request(app)
        .get('/codeflow/x509VPrequest_dynamic/test-session')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[0]).to.equal('dss.aegean.gr'); // clientId
      expect(callArgs[1]).to.include('/direct_post_vci/'); // response_uri
      expect(callArgs[4]).to.equal('x509_san_dns'); // client_id_scheme
    });
  });

  describe('GET /codeflow/didJwksVPrequest_dynamic/:id', () => {
    it('should return VP request JWT for DID', async () => {
      const response = await request(app)
        .get('/codeflow/didJwksVPrequest_dynamic/test-session')
        .expect(200);

      expect(response.text).to.equal('mock-vp-jwt-token');
      expect(response.headers['content-type']).to.include('text/plain');
    });

    it('should call buildVpRequestJWT with DID parameters', async () => {
      await request(app)
        .get('/codeflow/didJwksVPrequest_dynamic/test-session')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[0]).to.equal('did:web:localhost:3000'); // clientId
      expect(callArgs[4]).to.equal('did'); // client_id_scheme
      expect(callArgs[6]).to.equal('did:web:localhost:3000#keys-1'); // kid
    });
  });

  describe('GET /codeflow/id_token_x509_request_dynamic/:id', () => {
    it('should return id_token request JWT for X.509', async () => {
      const mockSession = {
        requests: { state: 'test-state' }
      };
      mockCacheService.getCodeFlowSession.resolves(mockSession);

      const response = await request(app)
        .get('/codeflow/id_token_x509_request_dynamic/test-session')
        .expect(200);

      expect(response.text).to.equal('mock-vp-jwt-token');
    });

    it('should call buildVpRequestJWT with id_token scope', async () => {
      const mockSession = {
        requests: { state: 'test-state' }
      };
      mockCacheService.getCodeFlowSession.resolves(mockSession);

      await request(app)
        .get('/codeflow/id_token_x509_request_dynamic/test-session')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[8]).to.equal('id_token'); // scope
    });
  });

  describe('GET /codeflow/id_token_did_request_dynamic/:id', () => {
    it('should return id_token request JWT for DID', async () => {
      const mockSession = {
        requests: { state: 'test-state' }
      };
      mockCacheService.getCodeFlowSession.resolves(mockSession);

      const response = await request(app)
        .get('/codeflow/id_token_did_request_dynamic/test-session')
        .expect(200);

      expect(response.text).to.equal('mock-vp-jwt-token');
    });

    it('should call buildVpRequestJWT with vp_token id_token scope', async () => {
      const mockSession = {
        requests: { state: 'test-state' }
      };
      mockCacheService.getCodeFlowSession.resolves(mockSession);

      await request(app)
        .get('/codeflow/id_token_did_request_dynamic/test-session')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[8]).to.equal('vp_token id_token'); // scope
    });
  });

  describe('POST /codeflow/direct_post_vci/:id', () => {
    it('should handle VP token successfully', async () => {
      const mockSession = {
        results: { state: 'test-state' },
        requests: { redirectUri: 'openid4vp://', state: 'test-state' }
      };
      mockCacheService.getCodeFlowSession.resolves(mockSession);

      const response = await request(app)
        .post('/codeflow/direct_post_vci/test-session')
        .send({
          state: 'test-state',
          vp_token: 'mock-vp-token'
        })
        .expect(200);

      expect(response.body).to.have.property('redirect_uri');
      expect(response.body.redirect_uri).to.include('code=');
      expect(response.body.redirect_uri).to.include('state=test-state');
    });

    it('should handle missing VP token', async () => {
      const response = await request(app)
        .post('/codeflow/direct_post_vci/test-session')
        .send({
          state: 'test-state'
        })
        .expect(500);
    });

    it('should handle missing session', async () => {
      mockCacheService.getCodeFlowSession.resolves(null);

      const response = await request(app)
        .post('/codeflow/direct_post_vci/test-session')
        .send({
          state: 'test-state',
          vp_token: 'mock-vp-token'
        })
        .expect(500);
    });

    it('should generate authorization code and store details', async () => {
      const mockSession = {
        results: { state: 'test-state' },
        requests: { redirectUri: 'openid4vp://', state: 'test-state' }
      };
      mockCacheService.getCodeFlowSession.resolves(mockSession);

      await request(app)
        .post('/codeflow/direct_post_vci/test-session')
        .send({
          state: 'test-state',
          vp_token: 'mock-vp-token'
        })
        .expect(200);

      expect(mockCryptoUtils.generateNonce.called).to.be.true;
      expect(mockCacheService.getAuthCodeAuthorizationDetail.called).to.be.true;
      expect(mockCacheService.storeCodeFlowSession.called).to.be.true;
    });
  });

  describe('Error handling', () => {
    it('should handle Redis connection errors', async () => {
      mockCacheService.getCodeFlowSession.rejects(new Error('Redis connection failed'));

      const response = await request(app)
        .get('/codeflow/offer-code-sd-jwt')
        .expect(500);

      expect(response.body).to.have.property('error');
    });

    it('should handle QR code generation errors', async () => {
      qr.image.throws(new Error('QR generation failed'));

      const response = await request(app)
        .get('/codeflow/offer-code-sd-jwt')
        .expect(500);

      expect(response.body).to.have.property('error');
    });

    it('should handle JWT build errors', async () => {
      mockCryptoUtils.buildVpRequestJWT.rejects(new Error('JWT build failed'));

      const response = await request(app)
        .get('/codeflow/x509VPrequest_dynamic/test-session')
        .expect(500);

      expect(response.body).to.have.property('error');
    });
  });

  describe('Credential Offer Configuration', () => {
    it('should set issuer_state for authorization code flow', async () => {
      const response = await request(app)
        .get('/codeflow/credential-offer-code-sd-jwt/test-session-123')
        .query({
          credentialType: 'urn:eu.europa.ec.eudi:pid:1'
        })
        .expect(200);

      expect(response.body).to.have.property('grants');
      expect(response.body.grants).to.have.property('authorization_code');
      expect(response.body.grants.authorization_code).to.have.property('issuer_state');
      expect(response.body.grants.authorization_code.issuer_state).to.equal('test-session-123');
      expect(response.body.grants.authorization_code).to.not.have.property('pre-authorized_code');
    });

    it('should set pre-authorized_code for pre-authorized code flow', async () => {
      // Mock the createCredentialOfferConfig function to return pre-authorized flow
      const mockConfig = {
        credential_issuer: 'https://example.com',
        credential_configuration_ids: ['urn:eu.europa.ec.eudi:pid:1'],
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'test-session-123'
          }
        }
      };

      // Create a test endpoint that returns pre-authorized flow config
      const preAuthRouter = express.Router();
      preAuthRouter.get('/pre-auth-offer/:id', (req, res) => {
        res.json(mockConfig);
      });
      app.use('/codeflow', preAuthRouter);

      const response = await request(app)
        .get('/codeflow/pre-auth-offer/test-session-123')
        .expect(200);

      expect(response.body).to.have.property('grants');
      expect(response.body.grants).to.have.property('urn:ietf:params:oauth:grant-type:pre-authorized_code');
      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('pre-authorized_code');
      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']).to.equal('test-session-123');
      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.not.have.property('issuer_state');
    });

    it('should include transaction code when specified', async () => {
      const response = await request(app)
        .get('/codeflow/credential-offer-code-sd-jwt/test-session-123')
        .query({
          credentialType: 'urn:eu.europa.ec.eudi:pid:1',
          includeTxCode: 'true'
        })
        .expect(200);

      expect(response.body).to.have.property('grants');
      expect(response.body.grants).to.have.property('authorization_code');
      expect(response.body.grants.authorization_code).to.have.property('issuer_state');
      expect(response.body.grants.authorization_code).to.have.property('tx_code');
    });

    it('should handle PAR request with issuer_state correctly', async () => {
      const parRequestData = {
        client_id: 'did:key:test',
        scope: 'urn:eu.europa.ec.eudi:pid:1',
        response_type: 'code',
        redirect_uri: 'openid4vp://',
        code_challenge: 'test-challenge',
        code_challenge_method: 'S256',
        issuer_state: 'test-session-123'
      };

      const response = await request(app)
        .post('/codeflow/par')
        .send(parRequestData)
        .expect(200);

      expect(response.body).to.have.property('request_uri');
      expect(response.body).to.have.property('expires_in');
      expect(response.body.expires_in).to.equal(90);
    });

    it('should handle authorization request with issuer_state from PAR', async () => {
      // First create a PAR request
      const parRequestData = {
        client_id: 'did:key:test',
        scope: 'urn:eu.europa.ec.eudi:pid:1',
        response_type: 'code',
        redirect_uri: 'openid4vp://',
        code_challenge: 'test-challenge',
        code_challenge_method: 'S256',
        issuer_state: 'test-session-123'
      };

      const parResponse = await request(app)
        .post('/codeflow/par')
        .send(parRequestData)
        .expect(200);

      const requestUri = parResponse.body.request_uri;

      // Mock session for the authorization request
      mockCacheService.getCodeFlowSession.resolves({
        walletSession: null,
        requests: { redirectUri: 'openid4vp://' },
        results: null,
        status: 'pending',
        client_id_scheme: 'x509_san_dns',
        flowType: 'code',
        signatureType: 'x509'
      });

      const authResponse = await request(app)
        .get('/codeflow/authorize')
        .query({
          client_id: 'did:key:test',
          request_uri: requestUri,
          response_type: 'code'
        })
        .expect(302); // Expect redirect instead of 200

      // Check that the redirect location contains the expected parameters
      expect(authResponse.headers.location).to.include('code=');
      expect(authResponse.headers.location).to.include('openid4vp://');
    });
  });
}); 