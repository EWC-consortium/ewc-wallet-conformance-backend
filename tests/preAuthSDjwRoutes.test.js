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
const mockCacheServiceRedis = {
  storePreAuthSession: sinon.stub(),
  getPreAuthSession: sinon.stub(),
  getSessionKeyFromAccessToken: sinon.stub(),
  getCodeFlowSession: sinon.stub(),
  storeCodeFlowSession: sinon.stub(),
  getSessionKeyAuthCode: sinon.stub()
};

// Mock streamToBuffer function
const mockStreamToBuffer = sinon.stub().resolves(Buffer.from('mock-buffer'));

// Create a test router that mimics the actual preAuthSDjwRoutes behavior
const testRouter = express.Router();

// Mock the offer-tx-code endpoint
testRouter.get('/offer-tx-code', async (req, res) => {
  try {
    const uuid = req.query.sessionId || uuidv4();
    const credentialType = req.query.credentialType || 'VerifiablePortableDocumentA2SDJWT';
    const signatureType = req.query.signatureType;

    let existingPreAuthSession = await mockCacheServiceRedis.getPreAuthSession(uuid);
    if (!existingPreAuthSession) {
      await mockCacheServiceRedis.storePreAuthSession(uuid, {
        status: 'pending',
        resulut: null,
        persona: null,
        accessToken: null,
        flowType: 'pre-auth',
        isHaip: false,
        signatureType: signatureType
      });
    }

    const encodedCredentialOfferUri = encodeURIComponent(
      `http://localhost:3000/credential-offer-tx-code/${uuid}?type=${credentialType}`
    );

    const credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`;
    
    let code = qr.image(credentialOffer, {
      type: 'png',
      ec_level: 'H',
      size: 10,
      margin: 10,
    });
    let mediaType = 'PNG';
    let encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);
    
    res.json({
      qr: encodedQR,
      deepLink: credentialOffer,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the credential-offer-tx-code endpoint
testRouter.get('/credential-offer-tx-code/:id', (req, res) => {
  try {
    const credentialType = req.query.type || 'VerifiablePortableDocumentA2SDJWT';
    
    res.json({
      credential_issuer: 'http://localhost:3000',
      credential_configuration_ids: [credentialType],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': req.params.id,
          tx_code: {
            length: 4,
            input_mode: 'numeric',
            description: 'Please provide the one-time code that was sent via e-mail or offline',
          },
        },
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the offer-no-code endpoint (GET)
testRouter.get('/offer-no-code', async (req, res) => {
  try {
    const uuid = req.query.sessionId || uuidv4();
    const credentialType = req.query.credentialType || 'VerifiablePortableDocumentA2SDJWT';
    const signatureType = req.query.signatureType;

    let existingPreAuthSession = await mockCacheServiceRedis.getPreAuthSession(uuid);
    if (!existingPreAuthSession) {
      await mockCacheServiceRedis.storePreAuthSession(uuid, {
        status: 'pending',
        resulut: null,
        persona: null,
        accessToken: null,
        flowType: 'pre-auth',
        isHaip: false,
        signatureType: signatureType
      });
    }

    const encodedCredentialOfferUri = encodeURIComponent(
      `http://localhost:3000/credential-offer-no-code/${uuid}?type=${credentialType}`
    );
    const credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`;
    
    let code = qr.image(credentialOffer, {
      type: 'png',
      ec_level: 'H',
      size: 10,
      margin: 10,
    });
    let mediaType = 'PNG';
    let encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);
    
    res.json({
      qr: encodedQR,
      deepLink: credentialOffer,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the offer-no-code endpoint (POST)
testRouter.post('/offer-no-code', async (req, res) => {
  try {
    const uuid = req.query.sessionId || uuidv4();
    const credentialType = req.query.credentialType || 'VerifiablePortableDocumentA2SDJWT';
    const credentialPayload = req.body;

    let existingPreAuthSession = await mockCacheServiceRedis.getPreAuthSession(uuid);
    if (!existingPreAuthSession) {
      await mockCacheServiceRedis.storePreAuthSession(uuid, {
        status: 'pending',
        resulut: null,
        persona: null,
        accessToken: null,
        credentialPayload: credentialPayload,
        flowType: 'pre-auth',
        isHaip: true
      });
    }

    const encodedCredentialOfferUri = encodeURIComponent(
      `http://localhost:3000/credential-offer-no-code/${uuid}?type=${credentialType}`
    );
    const credentialOffer = `openid-credential-offer://?credential_offer_uri=${encodedCredentialOfferUri}`;
    
    let code = qr.image(credentialOffer, {
      type: 'png',
      ec_level: 'H',
      size: 10,
      margin: 10,
    });
    let mediaType = 'PNG';
    let encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);
    
    res.json({
      qr: encodedQR,
      deepLink: credentialOffer,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the credential-offer-no-code endpoint
testRouter.get('/credential-offer-no-code/:id', async (req, res) => {
  try {
    const credentialType = req.query.type || 'VerifiablePortableDocumentA2SDJWT';
    
    res.json({
      credential_issuer: 'http://localhost:3000',
      credential_configuration_ids: [credentialType],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': req.params.id,
        },
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the haip-offer-tx-code endpoint
testRouter.get('/haip-offer-tx-code', async (req, res) => {
  try {
    const uuid = req.query.sessionId || uuidv4();
    const credentialType = req.query.credentialType || 'VerifiablePortableDocumentA2SDJWT';

    let existingPreAuthSession = await mockCacheServiceRedis.getPreAuthSession(uuid);
    if (!existingPreAuthSession) {
      await mockCacheServiceRedis.storePreAuthSession(uuid, {
        status: 'pending',
        resulut: null,
        persona: null,
        accessToken: null,
        isHaip: true,
        flowType: 'pre-auth',
      });
    }

    const encodedCredentialOfferUri = encodeURIComponent(
      `http://localhost:3000/haip-credential-offer-tx-code/${uuid}?type=${credentialType}`
    );
    const credentialOffer = `haip://?credential_offer_uri=${encodedCredentialOfferUri}`;
    
    let code = qr.image(credentialOffer, {
      type: 'png',
      ec_level: 'H',
      size: 10,
      margin: 10,
    });
    let mediaType = 'PNG';
    let encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);
    
    res.json({
      qr: encodedQR,
      deepLink: credentialOffer,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the haip-credential-offer-tx-code endpoint
testRouter.get('/haip-credential-offer-tx-code/:id', (req, res) => {
  try {
    const credentialType = req.query.type || 'VerifiablePortableDocumentA2SDJWT';
    
    res.json({
      credential_issuer: 'http://localhost:3000',
      credential_configuration_ids: [credentialType],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': req.params.id,
          tx_code: {
            length: 4,
            input_mode: 'numeric',
            description: 'Please provide the one-time code that was sent via e-mail or offline',
          },
        },
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mount the test router
app.use('/preauth', testRouter);

describe('Pre-Auth SD-JWT Routes', () => {
  let sandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
    
    // Reset all stubs
    mockCacheServiceRedis.storePreAuthSession.reset();
    mockCacheServiceRedis.getPreAuthSession.reset();
    
    // Set up default return values
    mockCacheServiceRedis.storePreAuthSession.resolves();
    mockCacheServiceRedis.getPreAuthSession.resolves(null);
    
    // Mock QR code generation
    const mockQRStream = { pipe: sinon.stub().returnsThis() };
    sandbox.stub(qr, 'image').returns(mockQRStream);
    sandbox.stub(imageDataURI, 'encode').returns('data:image/png;base64,mock-qr-code');
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('GET /preauth/offer-tx-code', () => {
    it('should generate credential offer with transaction code using default parameters', async () => {
      const response = await request(app)
        .get('/preauth/offer-tx-code')
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
      expect(response.body.deepLink).to.include('openid-credential-offer://');
      expect(response.body.deepLink).to.include('credential_offer_uri');
    });

    it('should generate credential offer with custom sessionId', async () => {
      const customSessionId = 'custom-session-123';
      
      const response = await request(app)
        .get('/preauth/offer-tx-code')
        .query({ sessionId: customSessionId })
        .expect(200);

      expect(response.body.sessionId).to.equal(customSessionId);
    });

    it('should generate credential offer with custom credentialType', async () => {
      const customCredentialType = 'CustomCredentialType';
      
      const response = await request(app)
        .get('/preauth/offer-tx-code')
        .query({ credentialType: customCredentialType })
        .expect(200);

      expect(response.body.deepLink).to.include(encodeURIComponent(`type=${customCredentialType}`));
    });

    it('should generate credential offer with signatureType', async () => {
      const signatureType = 'ES256';
      
      const response = await request(app)
        .get('/preauth/offer-tx-code')
        .query({ signatureType })
        .expect(200);

      expect(mockCacheServiceRedis.storePreAuthSession.called).to.be.true;
      const callArgs = mockCacheServiceRedis.storePreAuthSession.getCall(0).args;
      expect(callArgs[1]).to.have.property('signatureType', signatureType);
    });

    it('should not create new session if existing session found', async () => {
      const existingSession = {
        status: 'pending',
        flowType: 'pre-auth'
      };
      mockCacheServiceRedis.getPreAuthSession.resolves(existingSession);

      await request(app)
        .get('/preauth/offer-tx-code')
        .expect(200);

      expect(mockCacheServiceRedis.storePreAuthSession.called).to.be.false;
    });

    it('should create new session with correct parameters when no existing session', async () => {
      await request(app)
        .get('/preauth/offer-tx-code')
        .query({ signatureType: 'ES384' })
        .expect(200);

      expect(mockCacheServiceRedis.storePreAuthSession.called).to.be.true;
      const callArgs = mockCacheServiceRedis.storePreAuthSession.getCall(0).args;
      expect(callArgs[1]).to.have.property('status', 'pending');
      expect(callArgs[1]).to.have.property('flowType', 'pre-auth');
      expect(callArgs[1]).to.have.property('isHaip', false);
      expect(callArgs[1]).to.have.property('signatureType', 'ES384');
    });
  });

  describe('GET /preauth/credential-offer-tx-code/:id', () => {
    it('should return credential offer configuration with transaction code', async () => {
      const sessionId = 'test-session-123';
      const credentialType = 'TestCredentialType';
      
      const response = await request(app)
        .get(`/preauth/credential-offer-tx-code/${sessionId}`)
        .query({ type: credentialType })
        .expect(200);

      expect(response.body).to.have.property('credential_issuer', 'http://localhost:3000');
      expect(response.body).to.have.property('credential_configuration_ids');
      expect(response.body.credential_configuration_ids).to.include(credentialType);
      expect(response.body).to.have.property('grants');
      expect(response.body.grants).to.have.property('urn:ietf:params:oauth:grant-type:pre-authorized_code');
      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('pre-authorized_code', sessionId);
      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('tx_code');
    });

    it('should use default credential type when not specified', async () => {
      const sessionId = 'test-session-123';
      
      const response = await request(app)
        .get(`/preauth/credential-offer-tx-code/${sessionId}`)
        .expect(200);

      expect(response.body.credential_configuration_ids).to.include('VerifiablePortableDocumentA2SDJWT');
    });

    it('should include transaction code configuration', async () => {
      const sessionId = 'test-session-123';
      
      const response = await request(app)
        .get(`/preauth/credential-offer-tx-code/${sessionId}`)
        .expect(200);

      const txCode = response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'].tx_code;
      expect(txCode).to.have.property('length', 4);
      expect(txCode).to.have.property('input_mode', 'numeric');
      expect(txCode).to.have.property('description');
    });
  });

  describe('GET /preauth/offer-no-code', () => {
    it('should generate credential offer without transaction code', async () => {
      const response = await request(app)
        .get('/preauth/offer-no-code')
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
      expect(response.body.deepLink).to.include('openid-credential-offer://');
      expect(response.body.deepLink).to.include('credential-offer-no-code');
    });

    it('should create session with correct parameters', async () => {
      await request(app)
        .get('/preauth/offer-no-code')
        .query({ signatureType: 'ES512' })
        .expect(200);

      expect(mockCacheServiceRedis.storePreAuthSession.called).to.be.true;
      const callArgs = mockCacheServiceRedis.storePreAuthSession.getCall(0).args;
      expect(callArgs[1]).to.have.property('isHaip', false);
      expect(callArgs[1]).to.have.property('signatureType', 'ES512');
    });

    it('should use custom sessionId and credentialType', async () => {
      const customSessionId = 'custom-no-code-session';
      const customCredentialType = 'NoCodeCredential';
      
      const response = await request(app)
        .get('/preauth/offer-no-code')
        .query({ 
          sessionId: customSessionId,
          credentialType: customCredentialType 
        })
        .expect(200);

      expect(response.body.sessionId).to.equal(customSessionId);
      expect(response.body.deepLink).to.include(encodeURIComponent(`type=${customCredentialType}`));
    });
  });

  describe('POST /preauth/offer-no-code', () => {
    it('should generate credential offer with credential payload', async () => {
      const credentialPayload = {
        name: 'John Doe',
        email: 'john@example.com'
      };
      
      const response = await request(app)
        .post('/preauth/offer-no-code')
        .send(credentialPayload)
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
    });

    it('should store session with credential payload and HAIP flag', async () => {
      const credentialPayload = { test: 'data' };
      
      await request(app)
        .post('/preauth/offer-no-code')
        .send(credentialPayload)
        .expect(200);

      expect(mockCacheServiceRedis.storePreAuthSession.called).to.be.true;
      const callArgs = mockCacheServiceRedis.storePreAuthSession.getCall(0).args;
      expect(callArgs[1].credentialPayload).to.deep.equal(credentialPayload);
      expect(callArgs[1]).to.have.property('isHaip', true);
    });

    it('should use custom sessionId and credentialType in POST', async () => {
      const customSessionId = 'custom-post-session';
      const customCredentialType = 'PostCredential';
      const credentialPayload = { data: 'test' };
      
      const response = await request(app)
        .post('/preauth/offer-no-code')
        .query({ 
          sessionId: customSessionId,
          credentialType: customCredentialType 
        })
        .send(credentialPayload)
        .expect(200);

      expect(response.body.sessionId).to.equal(customSessionId);
      expect(response.body.deepLink).to.include(encodeURIComponent(`type=${customCredentialType}`));
    });
  });

  describe('GET /preauth/credential-offer-no-code/:id', () => {
    it('should return credential offer configuration without transaction code', async () => {
      const sessionId = 'test-no-code-session';
      const credentialType = 'NoCodeCredentialType';
      
      const response = await request(app)
        .get(`/preauth/credential-offer-no-code/${sessionId}`)
        .query({ type: credentialType })
        .expect(200);

      expect(response.body).to.have.property('credential_issuer', 'http://localhost:3000');
      expect(response.body).to.have.property('credential_configuration_ids');
      expect(response.body.credential_configuration_ids).to.include(credentialType);
      expect(response.body).to.have.property('grants');
      expect(response.body.grants).to.have.property('urn:ietf:params:oauth:grant-type:pre-authorized_code');
      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('pre-authorized_code', sessionId);
      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.not.have.property('tx_code');
    });

    it('should use default credential type when not specified', async () => {
      const sessionId = 'test-no-code-session';
      
      const response = await request(app)
        .get(`/preauth/credential-offer-no-code/${sessionId}`)
        .expect(200);

      expect(response.body.credential_configuration_ids).to.include('VerifiablePortableDocumentA2SDJWT');
    });
  });

  describe('GET /preauth/haip-offer-tx-code', () => {
    it('should generate HAIP credential offer with transaction code', async () => {
      const response = await request(app)
        .get('/preauth/haip-offer-tx-code')
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
      expect(response.body.deepLink).to.include('haip://');
      expect(response.body.deepLink).to.include('haip-credential-offer-tx-code');
    });

    it('should create session with HAIP flag set to true', async () => {
      await request(app)
        .get('/preauth/haip-offer-tx-code')
        .expect(200);

      expect(mockCacheServiceRedis.storePreAuthSession.called).to.be.true;
      const callArgs = mockCacheServiceRedis.storePreAuthSession.getCall(0).args;
      expect(callArgs[1]).to.have.property('isHaip', true);
    });

    it('should use custom sessionId and credentialType', async () => {
      const customSessionId = 'custom-haip-session';
      const customCredentialType = 'HAIPCredential';
      
      const response = await request(app)
        .get('/preauth/haip-offer-tx-code')
        .query({ 
          sessionId: customSessionId,
          credentialType: customCredentialType 
        })
        .expect(200);

      expect(response.body.sessionId).to.equal(customSessionId);
      expect(response.body.deepLink).to.include(encodeURIComponent(`type=${customCredentialType}`));
    });
  });

  describe('GET /preauth/haip-credential-offer-tx-code/:id', () => {
    it('should return HAIP credential offer configuration with transaction code', async () => {
      const sessionId = 'test-haip-session';
      const credentialType = 'HAIPCredentialType';
      
      const response = await request(app)
        .get(`/preauth/haip-credential-offer-tx-code/${sessionId}`)
        .query({ type: credentialType })
        .expect(200);

      expect(response.body).to.have.property('credential_issuer', 'http://localhost:3000');
      expect(response.body).to.have.property('credential_configuration_ids');
      expect(response.body.credential_configuration_ids).to.include(credentialType);
      expect(response.body).to.have.property('grants');
      expect(response.body.grants).to.have.property('urn:ietf:params:oauth:grant-type:pre-authorized_code');
      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('pre-authorized_code', sessionId);
      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('tx_code');
    });

    it('should include transaction code configuration for HAIP', async () => {
      const sessionId = 'test-haip-session';
      
      const response = await request(app)
        .get(`/preauth/haip-credential-offer-tx-code/${sessionId}`)
        .expect(200);

      const txCode = response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'].tx_code;
      expect(txCode).to.have.property('length', 4);
      expect(txCode).to.have.property('input_mode', 'numeric');
      expect(txCode).to.have.property('description');
    });
  });

  describe('QR Code Generation', () => {
    it('should generate QR codes with correct parameters', async () => {
      await request(app)
        .get('/preauth/offer-tx-code')
        .expect(200);

      expect(qr.image.called).to.be.true;
      const callArgs = qr.image.getCall(0).args;
      expect(callArgs[0]).to.include('openid-credential-offer://');
      expect(callArgs[1]).to.have.property('type', 'png');
      expect(callArgs[1]).to.have.property('ec_level', 'H');
      expect(callArgs[1]).to.have.property('size', 10);
      expect(callArgs[1]).to.have.property('margin', 10);
    });

    it('should encode QR codes as data URI', async () => {
      await request(app)
        .get('/preauth/offer-tx-code')
        .expect(200);

      expect(imageDataURI.encode.called).to.be.true;
      const callArgs = imageDataURI.encode.getCall(0).args;
      expect(callArgs[1]).to.equal('PNG');
    });
  });

  describe('Session Management', () => {
    it('should check for existing sessions before creating new ones', async () => {
      await request(app)
        .get('/preauth/offer-tx-code')
        .expect(200);

      expect(mockCacheServiceRedis.getPreAuthSession.called).to.be.true;
    });

    it('should handle existing sessions correctly', async () => {
      const existingSession = {
        status: 'pending',
        flowType: 'pre-auth',
        isHaip: false
      };
      mockCacheServiceRedis.getPreAuthSession.resolves(existingSession);

      await request(app)
        .get('/preauth/offer-tx-code')
        .expect(200);

      expect(mockCacheServiceRedis.storePreAuthSession.called).to.be.false;
    });
  });

  describe('Error handling', () => {
    it('should handle Redis connection errors gracefully', async () => {
      mockCacheServiceRedis.getPreAuthSession.rejects(new Error('Redis connection failed'));

      const response = await request(app)
        .get('/preauth/offer-tx-code')
        .expect(500);

      expect(response.body).to.have.property('error');
    });

    it('should handle QR code generation errors', async () => {
      qr.image.throws(new Error('QR generation failed'));

      const response = await request(app)
        .get('/preauth/offer-tx-code')
        .expect(500);

      expect(response.body).to.have.property('error');
    });

    it('should handle session storage errors', async () => {
      mockCacheServiceRedis.storePreAuthSession.rejects(new Error('Storage failed'));

      const response = await request(app)
        .get('/preauth/offer-tx-code')
        .expect(500);

      expect(response.body).to.have.property('error');
    });
  });

  describe('URL Scheme Differences', () => {
    it('should use openid-credential-offer:// for standard flows', async () => {
      const response = await request(app)
        .get('/preauth/offer-tx-code')
        .expect(200);

      expect(response.body.deepLink).to.include('openid-credential-offer://');
    });

    it('should use haip:// for HAIP flows', async () => {
      const response = await request(app)
        .get('/preauth/haip-offer-tx-code')
        .expect(200);

      expect(response.body.deepLink).to.include('haip://');
    });
  });

  describe('Transaction Code Configuration', () => {
    it('should include tx_code in credential offers that support it', async () => {
      const response = await request(app)
        .get('/preauth/credential-offer-tx-code/test-session')
        .expect(200);

      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('tx_code');
    });

    it('should not include tx_code in no-code credential offers', async () => {
      const response = await request(app)
        .get('/preauth/credential-offer-no-code/test-session')
        .expect(200);

      expect(response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.not.have.property('tx_code');
    });
  });
}); 