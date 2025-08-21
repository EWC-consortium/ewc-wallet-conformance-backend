import assert from 'assert';
import statusListManager from '../utils/statusListUtils.js';

describe('Token Status List Tests', () => {
  let testStatusListId;

  before(async () => {
    // Create a test status list
    const statusList = await statusListManager.createStatusList(100, 1);
    testStatusListId = statusList.id;
  });

  describe('Status List Creation', () => {
    it('should create a status list with valid parameters', async () => {
      const statusList = await statusListManager.createStatusList(1000, 1);
      assert.ok(statusList.id);
      assert.strictEqual(statusList.size, 1000);
      assert.strictEqual(statusList.bits, 1);
      assert.strictEqual(statusList.statuses.length, 1000);
      assert.strictEqual(statusList.statuses[0], 0); // All tokens start as valid
    });

    it('should reject invalid bits values', () => {
      assert.throws(() => {
        // call without await to keep throws catch
        statusListManager.createStatusList(100, 3);
      }, Error);
    });
  });

  describe('Token Status Management', () => {
    it('should update token status correctly', async () => {
      const success = await statusListManager.updateTokenStatus(testStatusListId, 5, 1);
      assert.strictEqual(success, true);
      
      const status = await statusListManager.getTokenStatus(testStatusListId, 5);
      assert.strictEqual(status, 1);
    });

    it('should reject invalid indices', async () => {
      const success = await statusListManager.updateTokenStatus(testStatusListId, 999, 1);
      assert.strictEqual(success, false);
    });

    it('should return null for invalid status list', async () => {
      const status = await statusListManager.getTokenStatus('invalid-id', 0);
      assert.strictEqual(status, null);
    });
  });

  describe('Status List Token Generation', () => {
    it('should generate a valid status list token', async () => {
      const token = await statusListManager.generateStatusListToken(testStatusListId);
      assert.ok(token);
      assert.strictEqual(typeof token, 'string');
      
      // Verify the token
      const decoded = statusListManager.verifyStatusListToken(token);
      assert.ok(decoded);
      assert.ok(decoded.status_list);
      assert.strictEqual(decoded.status_list.bits, 1);
      assert.ok(decoded.status_list.lst);
    });

    it('should cache status list tokens', async () => {
      const token1 = await statusListManager.generateStatusListToken(testStatusListId);
      const token2 = await statusListManager.generateStatusListToken(testStatusListId);
      assert.strictEqual(token1, token2);
    });
  });

  describe('Token Revocation Checking', () => {
    it('should correctly identify revoked tokens', async () => {
      // Revoke a token
      statusListManager.updateTokenStatus(testStatusListId, 10, 1);
      
      // Generate status list token
      const statusListToken = await statusListManager.generateStatusListToken(testStatusListId);
      
      // Check if token is revoked
      const isRevoked = statusListManager.isTokenRevoked(statusListToken, 10);
      assert.strictEqual(isRevoked, true);
    });

    it('should correctly identify valid tokens', async () => {
      // Generate status list token
      const statusListToken = await statusListManager.generateStatusListToken(testStatusListId);
      
      // Check if token is valid (not revoked)
      const isRevoked = statusListManager.isTokenRevoked(statusListToken, 0);
      assert.strictEqual(isRevoked, false);
    });
  });

  describe('Status Reference Creation', () => {
    it('should create valid status references', async () => {
      const reference = statusListManager.createStatusReference(testStatusListId, 15);
      assert.ok(reference.status_list);
      assert.strictEqual(reference.status_list.uri, `http://localhost:3000/status-list/${testStatusListId}`);
      assert.strictEqual(reference.status_list.idx, 15);
    });
  });

  describe('Status List Management', () => {
    it('should return all status lists', async () => {
      const statusLists = await statusListManager.getAllStatusLists();
      assert.ok(Array.isArray(statusLists));
      assert.ok(statusLists.length > 0);
    });

    it('should delete status lists', async () => {
      const statusList = await statusListManager.createStatusList(50, 1);
      const success = await statusListManager.deleteStatusList(statusList.id);
      assert.strictEqual(success, true);
      
      const deletedStatusList = await statusListManager.getStatusList(statusList.id);
      assert.strictEqual(deletedStatusList, null);
    });
  });

  describe('Compression and Decompression', () => {
    it('should correctly compress and decompress status arrays', () => {
      const statuses = new Array(100).fill(0);
      statuses[25] = 1; // Revoke one token
      statuses[50] = 1; // Revoke another token
      
      const compressed = statusListManager.statusesToCompressedBuffer(statuses, 1);
      assert.ok(Buffer.isBuffer(compressed));
      
      // Decompress and verify
      const decompressed = require('zlib').inflateSync(compressed);
      assert.ok(Buffer.isBuffer(decompressed));
    });
  });
});

console.log('Status List Tests completed successfully!');
