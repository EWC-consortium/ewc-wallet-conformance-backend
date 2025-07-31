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
  buildVpRequestJWT: sinon.stub(),
  didKeyToJwks: sinon.stub()
};

const mockCacheService = {
  storeVPSession: sinon.stub(),
  getVPSession: sinon.stub()
};

const mockVpHelpers = {
  getSDsFromPresentationDef: sinon.stub()
};

// Mock streamToBuffer function
const mockStreamToBuffer = sinon.stub().resolves(Buffer.from('mock-buffer'));

// Create a test router that mimics the actual didRoutes behavior
const testRouter = express.Router();

// Helper function to create DID controller
function createDidController(serverURL) {
  let controller = serverURL;
  if (process.env.PROXY_PATH) {
    controller = serverURL.replace("/" + process.env.PROXY_PATH, "") + ":" + process.env.PROXY_PATH;
  }
  controller = controller.replace("https://", "");
  return controller;
}

// Mock the generateVPRequest endpoint
testRouter.get('/generateVPRequest', async (req, res) => {
  try {
    const uuid = req.query.sessionId || 'test-uuid-123';
    const responseMode = req.query.response_mode || 'direct_post';
    const nonce = mockCryptoUtils.generateNonce(16);

    const response_uri = `http://localhost:3000/direct_post/${uuid}`;
    const controller = createDidController('http://localhost:3000');
    const client_id = `did:web:${controller}`;
    const kid = `did:web:${controller}#keys-1`;

    // Store session data
    await mockCacheService.storeVPSession(uuid, {
      uuid: uuid,
      status: 'pending',
      claims: null,
      presentation_definition: { test: 'definition' },
      nonce: nonce,
      sdsRequested: mockVpHelpers.getSDsFromPresentationDef({ test: 'definition' }),
      response_mode: responseMode
    });

    // Build and sign the VP request JWT
    await mockCryptoUtils.buildVpRequestJWT(
      client_id,
      response_uri,
      { test: 'definition' },
      'mock-private-key',
      { test: 'metadata' },
      kid,
      'http://localhost:3000',
      'vp_token',
      nonce,
      null,
      null,
      responseMode
    );

    // Create the openid4vp:// URL
    const requestUri = `http://localhost:3000/did/VPrequest/${uuid}`;
    const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(
      requestUri
    )}&request_uri_method=post&client_id=${encodeURIComponent(client_id)}`;

    // Generate QR code
    let code = qr.image(vpRequest, {
      type: 'png',
      ec_level: 'M',
      size: 20,
      margin: 10,
    });
    let mediaType = 'PNG';
    let encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);
    
    res.json({
      qr: encodedQR,
      deepLink: vpRequest,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the generateVPRequestGET endpoint
testRouter.get('/generateVPRequestGET', async (req, res) => {
  try {
    const uuid = req.query.sessionId || 'test-uuid-123';
    const responseMode = req.query.response_mode || 'direct_post';
    const nonce = mockCryptoUtils.generateNonce(16);

    const response_uri = `http://localhost:3000/direct_post/${uuid}`;
    const controller = createDidController('http://localhost:3000');
    const client_id = `did:web:${controller}`;
    const kid = `did:web:${controller}#keys-1`;

    await mockCacheService.storeVPSession(uuid, {
      uuid: uuid,
      status: 'pending',
      claims: null,
      presentation_definition: { test: 'definition' },
      nonce: nonce,
      sdsRequested: mockVpHelpers.getSDsFromPresentationDef({ test: 'definition' }),
      response_mode: responseMode
    });

    await mockCryptoUtils.buildVpRequestJWT(
      client_id,
      response_uri,
      { test: 'definition' },
      'mock-private-key',
      { test: 'metadata' },
      kid,
      'http://localhost:3000',
      'vp_token',
      nonce,
      null,
      null,
      responseMode
    );

    const requestUri = `http://localhost:3000/did/VPrequest/${uuid}`;
    const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(
      requestUri
    )}&client_id=${encodeURIComponent(client_id)}`;

    let code = qr.image(vpRequest, {
      type: 'png',
      ec_level: 'M',
      size: 20,
      margin: 10,
    });
    let mediaType = 'PNG';
    let encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);

    res.json({
      qr: encodedQR,
      deepLink: vpRequest,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the generateVPRequestDCQL endpoint
testRouter.get('/generateVPRequestDCQL', async (req, res) => {
  try {
    const uuid = req.query.sessionId || 'test-uuid-123';
    const nonce = mockCryptoUtils.generateNonce(16);
    const responseMode = req.query.response_mode || 'direct_post';

    const response_uri = `http://localhost:3000/direct_post/${uuid}`;
    const controller = createDidController('http://localhost:3000');
    const client_id = `did:web:${controller}`;
    const kid = `did:web:${controller}#keys-1`;

    const dcql_query = {
      credentials: [
        {
          id: 'cmwallet',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['urn:eu.europa.ec.eudi:pid:1']
          },
          claims: [
            {
              path: ['family_name']
            }
          ]
        }
      ]
    };

    await mockCacheService.storeVPSession(uuid, {
      uuid: uuid,
      status: 'pending',
      claims: null,
      dcql_query: dcql_query,
      nonce: nonce,
      response_mode: responseMode
    });

    await mockCryptoUtils.buildVpRequestJWT(
      client_id,
      response_uri,
      null,
      'mock-private-key',
      { test: 'metadata' },
      kid,
      'http://localhost:3000',
      'vp_token',
      nonce,
      dcql_query,
      null,
      responseMode
    );

    const requestUri = `http://localhost:3000/did/VPrequest/${uuid}`;
    const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(
      requestUri
    )}&request_uri_method=post&client_id=${encodeURIComponent(client_id)}`;

    let code = qr.image(vpRequest, {
      type: 'png',
      ec_level: 'M',
      size: 20,
      margin: 10,
    });
    let mediaType = 'PNG';
    let encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);
    
    res.json({
      qr: encodedQR,
      deepLink: vpRequest,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock the generateVPRequestTransaction endpoint
testRouter.get('/generateVPRequestTransaction', async (req, res) => {
  try {
    const uuid = req.query.sessionId || 'test-uuid-123';
    const nonce = mockCryptoUtils.generateNonce(16);
    const responseMode = req.query.response_mode || 'direct_post';

    const response_uri = `http://localhost:3000/direct_post/${uuid}`;
    const controller = createDidController('http://localhost:3000');
    const client_id = `did:web:${controller}`;
    const kid = `did:web:${controller}#keys-1`;

    const presentation_definition = { test: 'definition' };
    const credentialIds = ['test-descriptor-1', 'test-descriptor-2'];
    const transactionDataObj = {
      type: 'qes_authorization',
      credential_ids: credentialIds,
      transaction_data_hashes_alg: ['sha-256'],
      purpose: 'Verification of identity',
      timestamp: new Date().toISOString(),
      transaction_id: 'test-transaction-id',
      documentDigests: [
        {
          hash: 'sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=',
          label: 'Example Contract',
          hashAlgorithmOID: '2.16.840.1.101.3.4.2.1',
          documentLocations: [
            {
              uri: 'https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374',
              method: {
                type: 'public'
              }
            }
          ],
          dtbsr: 'VYDl4oTeJ5TmIPCXKdTX1MSWRLI9CKYcyMRz6xlaGg'
        }
      ]
    };
    const base64UrlEncodedTxData = Buffer.from(JSON.stringify(transactionDataObj))
      .toString('base64url');

    await mockCacheService.storeVPSession(uuid, {
      uuid: uuid,
      status: 'pending',
      claims: null,
      presentation_definition: presentation_definition,
      nonce: nonce,
      transaction_data: [base64UrlEncodedTxData],
      response_mode: responseMode,
      sdsRequested: mockVpHelpers.getSDsFromPresentationDef(presentation_definition)
    });

    await mockCryptoUtils.buildVpRequestJWT(
      client_id,
      response_uri,
      presentation_definition,
      'mock-private-key',
      { test: 'metadata' },
      kid,
      'http://localhost:3000',
      'vp_token',
      nonce,
      null,
      [base64UrlEncodedTxData],
      responseMode
    );

    const requestUri = `http://localhost:3000/did/VPrequest/${uuid}`;
    const vpRequest = `openid4vp://?request_uri=${encodeURIComponent(
      requestUri
    )}&client_id=${encodeURIComponent(client_id)}`;

    let code = qr.image(vpRequest, {
      type: 'png',
      ec_level: 'M',
      size: 20,
      margin: 10,
    });
    let mediaType = 'PNG';
    let encodedQR = imageDataURI.encode(await mockStreamToBuffer(code), mediaType);
    
    res.json({
      qr: encodedQR,
      deepLink: vpRequest,
      sessionId: uuid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper function to process VP Request
async function generateDidVPRequest(uuid, clientMetadata, serverURL, wallet_nonce, wallet_metadata) {
  const vpSession = await mockCacheService.getVPSession(uuid);

  if (!vpSession) {
    return { error: 'Invalid session ID', status: 400 };
  }

  const response_uri = `${serverURL}/direct_post/${uuid}`;
  const controller = createDidController(serverURL);
  const client_id = `did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;
  
  const vpRequestJWT = await mockCryptoUtils.buildVpRequestJWT(
    client_id,
    response_uri,
    vpSession.presentation_definition,
    'mock-private-key',
    clientMetadata,
    kid,
    serverURL,
    'vp_token',
    vpSession.nonce,
    vpSession.dcql_query || null,
    vpSession.transaction_data || null,
    vpSession.response_mode,
    undefined,
    wallet_nonce,
    wallet_metadata
  );

  return { jwt: vpRequestJWT, status: 200 };
}

// Mock the VPrequest endpoint
testRouter.route('/VPrequest/:id')
  .post(async (req, res) => {
    try {
      const uuid = req.params.id;
      const { wallet_nonce, wallet_metadata } = req.body;

      const result = await generateDidVPRequest(uuid, { test: 'metadata' }, 'http://localhost:3000', wallet_nonce, wallet_metadata);

      if (result.error) {
        return res.status(result.status).json({ error: result.error });
      }
      res.type('application/oauth-authz-req+jwt').send(result.jwt);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  })
  .get(async (req, res) => {
    try {
      const uuid = req.params.id;
      const result = await generateDidVPRequest(uuid, { test: 'metadata' }, 'http://localhost:3000');

      if (result.error) {
        return res.status(result.status).json({ error: result.error });
      }
      res.type('application/oauth-authz-req+jwt').send(result.jwt);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

// Mount the test router
app.use('/did', testRouter);

describe('DID Routes', () => {
  let sandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
    
    // Reset all stubs
    mockCryptoUtils.generateNonce.reset();
    mockCryptoUtils.buildVpRequestJWT.reset();
    mockCryptoUtils.didKeyToJwks.reset();
    mockCacheService.storeVPSession.reset();
    mockCacheService.getVPSession.reset();
    mockVpHelpers.getSDsFromPresentationDef.reset();
    mockStreamToBuffer.reset();
    
    // Set up default return values
    mockCryptoUtils.generateNonce.returns('test-nonce-123');
    mockCryptoUtils.buildVpRequestJWT.resolves('mock-jwt-token');
    mockCryptoUtils.didKeyToJwks.returns({ keys: [] });
    mockCacheService.storeVPSession.resolves();
    mockVpHelpers.getSDsFromPresentationDef.returns(['field1', 'field2']);
    
    // Mock QR code generation
    const mockQRStream = { pipe: sinon.stub().returnsThis() };
    sandbox.stub(qr, 'image').returns(mockQRStream);
    sandbox.stub(imageDataURI, 'encode').returns('data:image/png;base64,mock-qr-code');
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('GET /did/generateVPRequest', () => {
    it('should generate VP request with default parameters', async () => {
      const response = await request(app)
        .get('/did/generateVPRequest')
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
      expect(response.body.sessionId).to.equal('test-uuid-123');
    });

    it('should generate VP request with custom sessionId', async () => {
      const customSessionId = 'custom-session-123';
      
      const response = await request(app)
        .get('/did/generateVPRequest')
        .query({ sessionId: customSessionId })
        .expect(200);

      expect(response.body.sessionId).to.equal(customSessionId);
    });

    it('should generate VP request with custom response_mode', async () => {
      const response = await request(app)
        .get('/did/generateVPRequest')
        .query({ response_mode: 'fragment' })
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
    });

    it('should call buildVpRequestJWT with correct parameters', async () => {
      await request(app)
        .get('/did/generateVPRequest')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[0]).to.include('did:web:'); // client_id should be DID-based
      expect(callArgs[1]).to.include('/direct_post/'); // response_uri
      expect(callArgs[2]).to.be.an('object'); // presentation_definition
      expect(callArgs[3]).to.equal('mock-private-key'); // privateKey
      expect(callArgs[5]).to.include('did:web:'); // kid should be DID-based
    });
  });

  describe('GET /did/generateVPRequestGET', () => {
    it('should generate VP request for GET method', async () => {
      const response = await request(app)
        .get('/did/generateVPRequestGET')
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
    });

    it('should store session with correct parameters', async () => {
      await request(app)
        .get('/did/generateVPRequestGET')
        .expect(200);

      expect(mockCacheService.storeVPSession.called).to.be.true;
      const callArgs = mockCacheService.storeVPSession.getCall(0).args;
      expect(callArgs[0]).to.equal('test-uuid-123'); // sessionId
      expect(callArgs[1]).to.have.property('uuid', 'test-uuid-123');
      expect(callArgs[1]).to.have.property('status', 'pending');
    });

    it('should call buildVpRequestJWT with DID parameters', async () => {
      await request(app)
        .get('/did/generateVPRequestGET')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[0]).to.include('did:web:'); // client_id
      expect(callArgs[5]).to.include('did:web:'); // kid
    });
  });

  describe('GET /did/generateVPRequestDCQL', () => {
    it('should generate VP request with DCQL query', async () => {
      const response = await request(app)
        .get('/did/generateVPRequestDCQL')
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
    });

    it('should store session with DCQL query', async () => {
      await request(app)
        .get('/did/generateVPRequestDCQL')
        .expect(200);

      expect(mockCacheService.storeVPSession.called).to.be.true;
      const callArgs = mockCacheService.storeVPSession.getCall(0).args;
      expect(callArgs[1]).to.have.property('dcql_query');
      expect(callArgs[1].dcql_query).to.have.property('credentials');
    });

    it('should call buildVpRequestJWT with DCQL query', async () => {
      await request(app)
        .get('/did/generateVPRequestDCQL')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[9]).to.have.property('credentials'); // dcql_query parameter
    });
  });

  describe('GET /did/generateVPRequestTransaction', () => {
    it('should generate VP request with transaction data', async () => {
      const response = await request(app)
        .get('/did/generateVPRequestTransaction')
        .expect(200);

      expect(response.body).to.have.property('qr');
      expect(response.body).to.have.property('deepLink');
      expect(response.body).to.have.property('sessionId');
    });

    it('should store session with transaction data', async () => {
      await request(app)
        .get('/did/generateVPRequestTransaction')
        .expect(200);

      expect(mockCacheService.storeVPSession.called).to.be.true;
      const callArgs = mockCacheService.storeVPSession.getCall(0).args;
      expect(callArgs[1]).to.have.property('transaction_data');
      expect(callArgs[1].transaction_data).to.be.an('array');
    });

    it('should call buildVpRequestJWT with transaction data', async () => {
      await request(app)
        .get('/did/generateVPRequestTransaction')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[10]).to.be.an('array'); // transaction_data parameter
    });
  });

  describe('POST /did/VPrequest/:id', () => {
    it('should return JWT for valid session', async () => {
      mockCacheService.getVPSession.resolves({
        uuid: 'test-session',
        nonce: 'test-nonce',
        presentation_definition: { test: 'definition' }
      });

      const response = await request(app)
        .post('/did/VPrequest/test-session')
        .send({ wallet_nonce: 'wallet-nonce' })
        .expect(200);

      expect(response.text).to.equal('mock-jwt-token');
    });

    it('should handle missing session', async () => {
      mockCacheService.getVPSession.resolves(null);

      const response = await request(app)
        .post('/did/VPrequest/invalid-session')
        .expect(400);

      expect(response.body).to.have.property('error', 'Invalid session ID');
    });

    it('should call buildVpRequestJWT with wallet parameters', async () => {
      mockCacheService.getVPSession.resolves({
        uuid: 'test-session',
        nonce: 'test-nonce',
        presentation_definition: { test: 'definition' }
      });

      await request(app)
        .post('/did/VPrequest/test-session')
        .send({ wallet_nonce: 'wallet-nonce', wallet_metadata: 'wallet-metadata' })
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[13]).to.equal('wallet-nonce'); // wallet_nonce parameter
      expect(callArgs[14]).to.equal('wallet-metadata'); // wallet_metadata parameter
    });

    it('should handle buildVpRequestJWT errors', async () => {
      mockCacheService.getVPSession.resolves({
        uuid: 'test-session',
        nonce: 'test-nonce',
        presentation_definition: { test: 'definition' }
      });
      mockCryptoUtils.buildVpRequestJWT.rejects(new Error('JWT build failed'));

      const response = await request(app)
        .post('/did/VPrequest/test-session')
        .expect(500);

      expect(response.body).to.have.property('error');
    });
  });

  describe('GET /did/VPrequest/:id', () => {
    it('should return JWT for valid session', async () => {
      mockCacheService.getVPSession.resolves({
        uuid: 'test-session',
        nonce: 'test-nonce',
        presentation_definition: { test: 'definition' }
      });

      const response = await request(app)
        .get('/did/VPrequest/test-session')
        .expect(200);

      expect(response.text).to.equal('mock-jwt-token');
    });

    it('should handle missing session', async () => {
      mockCacheService.getVPSession.resolves(null);

      const response = await request(app)
        .get('/did/VPrequest/invalid-session')
        .expect(400);

      expect(response.body).to.have.property('error', 'Invalid session ID');
    });

    it('should call buildVpRequestJWT without wallet parameters', async () => {
      mockCacheService.getVPSession.resolves({
        uuid: 'test-session',
        nonce: 'test-nonce',
        presentation_definition: { test: 'definition' }
      });

      await request(app)
        .get('/did/VPrequest/test-session')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[13]).to.be.undefined; // wallet_nonce should be undefined for GET
      expect(callArgs[14]).to.be.undefined; // wallet_metadata should be undefined for GET
    });
  });

  describe('DID-specific functionality', () => {
    it('should use DID-based client_id and kid', async () => {
      await request(app)
        .get('/did/generateVPRequest')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[0]).to.match(/^did:web:/); // client_id should be DID format
      expect(callArgs[5]).to.match(/^did:web:.*#keys-1$/); // kid should be DID format with key reference
    });

    it('should handle PROXY_PATH environment variable', async () => {
      // Temporarily set PROXY_PATH
      const originalProxyPath = process.env.PROXY_PATH;
      process.env.PROXY_PATH = 'proxy';

      await request(app)
        .get('/did/generateVPRequest')
        .expect(200);

      expect(mockCryptoUtils.buildVpRequestJWT.called).to.be.true;
      const callArgs = mockCryptoUtils.buildVpRequestJWT.getCall(0).args;
      expect(callArgs[0]).to.include('proxy'); // client_id should include proxy path

      // Restore original value
      if (originalProxyPath) {
        process.env.PROXY_PATH = originalProxyPath;
      } else {
        delete process.env.PROXY_PATH;
      }
    });
  });

  describe('Error handling', () => {
    it('should handle Redis connection errors', async () => {
      mockCacheService.storeVPSession.rejects(new Error('Redis connection failed'));

      const response = await request(app)
        .get('/did/generateVPRequest')
        .expect(500);

      expect(response.body).to.have.property('error');
    });

    it('should handle QR code generation errors', async () => {
      // Modify the existing stub to throw an error
      qr.image.throws(new Error('QR generation failed'));

      const response = await request(app)
        .get('/did/generateVPRequest')
        .expect(500);

      expect(response.body).to.have.property('error');
    });

    it('should handle JWT build errors', async () => {
      mockCryptoUtils.buildVpRequestJWT.rejects(new Error('JWT build failed'));

      const response = await request(app)
        .get('/did/generateVPRequest')
        .expect(500);

      expect(response.body).to.have.property('error');
    });
  });
}); 