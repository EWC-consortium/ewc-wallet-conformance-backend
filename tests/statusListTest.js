import assert from 'assert';
import statusListManager from '../utils/statusListUtils.js';

describe('Status List Implementation Validation', () => {
  let testStatusListId;

  before(async () => {
    // Create a test status list with explicit configuration
    const statusList = await statusListManager.createStatusList(100, 1, {
      test: true,
      iss: 'did:web:itb.ilabs.ai:rfc-issuer',
      kid: 'did:web:itb.ilabs.ai:rfc-issuer#keys-1'
    });
    testStatusListId = statusList.id;
  });

  after(async () => {
    if (testStatusListId) {
      await statusListManager.deleteStatusList(testStatusListId);
    }
  });

  describe('Status List Creation and Structure', () => {
    it('should create status list with correct metadata', async () => {
      const statusList = await statusListManager.getStatusList(testStatusListId);
      
      assert.ok(statusList);
      assert.strictEqual(statusList.size, 100);
      assert.strictEqual(statusList.bits, 1);
      assert.ok(statusList.iss);
      assert.ok(statusList.kid);
      assert.ok(statusList.iss.match(/^did:web:/));
      assert.ok(statusList.kid.match(/^did:web:/));
    });

    it('should use configured issuer and kid', async () => {
      const statusList = await statusListManager.getStatusList(testStatusListId);
      
      // Should use the explicitly configured values
      const expectedIssuer = 'did:web:itb.ilabs.ai:rfc-issuer';
      const expectedKid = 'did:web:itb.ilabs.ai:rfc-issuer#keys-1';
      assert.strictEqual(statusList.iss, expectedIssuer);
      assert.strictEqual(statusList.kid, expectedKid);
    });
  });

  describe('Status List Token Structure', () => {
    it('should have compressed status list structure', async () => {
      const statusList = await statusListManager.getStatusList(testStatusListId);
      
      // Test compression logic
      const compressedBuffer = statusListManager.statusesToCompressedBuffer(statusList.statuses, statusList.bits);
      assert.ok(Buffer.isBuffer(compressedBuffer));
      assert.ok(compressedBuffer.length > 0);
    });

    it('should have correct bits configuration', async () => {
      const statusList = await statusListManager.getStatusList(testStatusListId);
      
      assert.ok([1, 2, 4, 8].includes(statusList.bits));
    });
  });

  describe('Status Management', () => {
    it('should handle revocation correctly', async () => {
      const tokenIndex = 42;
      
      // Initially should not be revoked
      let status = await statusListManager.getTokenStatus(testStatusListId, tokenIndex);
      assert.strictEqual(status, 0); // 0 = valid
      
      // Revoke the token
      const success = await statusListManager.updateTokenStatus(testStatusListId, tokenIndex, 1);
      assert.strictEqual(success, true);
      
      // Should now be revoked
      status = await statusListManager.getTokenStatus(testStatusListId, tokenIndex);
      assert.strictEqual(status, 1); // 1 = revoked
      
      // Unrevoke the token
      await statusListManager.updateTokenStatus(testStatusListId, tokenIndex, 0);
      
      // Should not be revoked again
      status = await statusListManager.getTokenStatus(testStatusListId, tokenIndex);
      assert.strictEqual(status, 0); // 0 = valid
    });

    it('should reject invalid indices', async () => {
      const success = await statusListManager.updateTokenStatus(testStatusListId, 999, 1);
      assert.strictEqual(success, false);
    });
  });

  describe('Trust Management', () => {
    it('should establish trust through same issuer', async () => {
      const statusList = await statusListManager.getStatusList(testStatusListId);
      
      // The status list issuer should be the same as the credential issuer
      // This establishes trust that the issuer of the credential can also revoke it
      const statusListIssuer = statusList.iss;
      const credentialIssuer = 'did:web:itb.ilabs.ai:rfc-issuer';
      
      assert.strictEqual(statusListIssuer, credentialIssuer);
    });

    it('should use same key as credentials', async () => {
      const statusList = await statusListManager.getStatusList(testStatusListId);
      
      // The kid should reference the same key used in credentials
      const statusListKid = statusList.kid;
      const credentialKid = 'did:web:itb.ilabs.ai:rfc-issuer#keys-1';
      
      assert.strictEqual(statusListKid, credentialKid);
    });
  });

  describe('Key Resolution', () => {
    it('should support DID resolution for key verification', async () => {
      const statusList = await statusListManager.getStatusList(testStatusListId);
      
      // The kid should be a valid DID URL that can be resolved
      const kid = statusList.kid;
      assert.ok(kid.match(/^did:web:[^#]+#[^#]+$/));
      
      // The DID part should be resolvable
      const did = kid.split('#')[0];
      assert.ok(did.match(/^did:web:/));
    });
  });

  describe('Status Reference Creation', () => {
    it('should create valid status references', async () => {
      const reference = statusListManager.createStatusReference(testStatusListId, 15);
      assert.ok(reference.status_list);
      assert.ok(reference.status_list.uri.includes(`/status-list/${testStatusListId}`));
      assert.strictEqual(reference.status_list.idx, 15);
    });
  });

  describe('IETF Spec Compliance Validation', () => {
    it('should follow IETF spec recommendations for same entity', async () => {
      const statusList = await statusListManager.getStatusList(testStatusListId);
      
      // According to IETF spec 11.3:
      // "If the Issuer of the Referenced Token is the same entity as the Status Issuer, 
      // then the same key that is embedded into the Referenced Token may be used for the Status List Token"
      
      // Verify that we're using the same issuer and key
      assert.strictEqual(statusList.iss, 'did:web:itb.ilabs.ai:rfc-issuer');
      assert.strictEqual(statusList.kid, 'did:web:itb.ilabs.ai:rfc-issuer#keys-1');
      
      // The kid should reference the same key as used in credentials
      assert.ok(statusList.kid.includes('#keys-1'));
    });

    it('should support proper key resolution mechanisms', async () => {
      const statusList = await statusListManager.getStatusList(testStatusListId);
      
      // Should have either kid or x5c for key resolution
      assert.ok(statusList.kid || statusList.x5c);
      
      // For did:web, should have kid
      assert.ok(statusList.kid);
      assert.ok(statusList.kid.startsWith('did:web:'));
    });
  });

  describe('Aligned Status List Creation', () => {
    it('should create aligned status lists when method is available', async () => {
      // Test that the createAlignedStatusList method exists and works
      if (typeof statusListManager.createAlignedStatusList === 'function') {
        const alignedStatusList = await statusListManager.createAlignedStatusList(50, 1, {
          test: true
        });
        
        assert.ok(alignedStatusList);
        assert.strictEqual(alignedStatusList.size, 50);
        assert.strictEqual(alignedStatusList.bits, 1);
        
        // Clean up
        await statusListManager.deleteStatusList(alignedStatusList.id);
      }
    });
  });

  describe('Signature Type Alignment', () => {
    it('should use same signature type as credential for did:web', async () => {
      const sessionObject = {
        signatureType: 'did:web',
        isHaip: false
      };
      
      const statusList = await statusListManager.createAlignedStatusList(50, 1, {
        test: true
      }, sessionObject);
      
      assert.ok(statusList);
      assert.strictEqual(statusList.iss, 'did:web:localhost:3000');
      assert.strictEqual(statusList.kid, 'did:web:localhost:3000#keys-1');
      
      // Clean up
      await statusListManager.deleteStatusList(statusList.id);
    });

    it('should use same signature type as credential for did:jwk', async () => {
      const sessionObject = {
        signatureType: 'did:jwk',
        isHaip: false
      };
      
      const statusList = await statusListManager.createAlignedStatusList(50, 1, {
        test: true
      }, sessionObject);
      
      assert.ok(statusList);
      assert.ok(statusList.iss.startsWith('did:jwk:'));
      assert.ok(statusList.kid.startsWith('did:jwk:'));
      assert.ok(statusList.kid.endsWith('#0'));
      
      // Clean up
      await statusListManager.deleteStatusList(statusList.id);
    });

    it('should use same signature type as credential for x509', async () => {
      const sessionObject = {
        signatureType: 'x509',
        isHaip: true
      };
      
      const statusList = await statusListManager.createAlignedStatusList(50, 1, {
        test: true
      }, sessionObject);
      
      assert.ok(statusList);
      assert.strictEqual(statusList.iss, 'http://localhost:3000');
      assert.ok(statusList.x5c);
      
      // Clean up
      await statusListManager.deleteStatusList(statusList.id);
    });

    it('should handle HAIP x509 signature type correctly', async () => {
      const sessionObject = {
        signatureType: 'did:web', // This should be overridden by HAIP logic
        isHaip: true
      };
      
      // Mock environment to enable x509
      const originalIssuerSignatureType = process.env.ISSUER_SIGNATURE_TYPE;
      process.env.ISSUER_SIGNATURE_TYPE = 'x509';
      
      try {
        const statusList = await statusListManager.createAlignedStatusList(50, 1, {
          test: true
        }, sessionObject);
        
        assert.ok(statusList);
        assert.strictEqual(statusList.iss, 'http://localhost:3000');
        assert.ok(statusList.x5c);
        
        // Clean up
        await statusListManager.deleteStatusList(statusList.id);
      } finally {
        // Restore environment
        if (originalIssuerSignatureType) {
          process.env.ISSUER_SIGNATURE_TYPE = originalIssuerSignatureType;
        } else {
          delete process.env.ISSUER_SIGNATURE_TYPE;
        }
      }
    });
  });
});
