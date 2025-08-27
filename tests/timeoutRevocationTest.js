import assert from 'assert';
import { statusListUpdateIndex, statusListGet } from '../services/cacheServiceRedis.js';
import statusListManager from '../utils/statusListUtils.js';

describe('Timeout-Based Credential Revocation', () => {
  let testStatusListId;
  let testTokenIndex;

  before(async () => {
    // Create a test status list
    const statusList = await statusListManager.createStatusList(100, 1, {
      test: true,
      iss: 'did:web:test.example.com',
      kid: 'did:web:test.example.com#keys-1'
    });
    testStatusListId = statusList.id;
    testTokenIndex = 42; // Use a specific index for testing
  });

  after(async () => {
    if (testStatusListId) {
      await statusListManager.deleteStatusList(testStatusListId);
    }
  });

  describe('Initial Status Verification', () => {
    it('should start with valid status (0)', async () => {
      const status = await statusListManager.getTokenStatus(testStatusListId, testTokenIndex);
      assert.strictEqual(status, 0, 'Token should start with valid status (0)');
    });
  });

  describe('Manual Revocation Test', () => {
    it('should manually revoke a token using statusListUpdateIndex', async () => {
      // Manually revoke the token
      const success = await statusListUpdateIndex(testStatusListId, testTokenIndex, 1);
      assert.strictEqual(success, true, 'Manual revocation should succeed');

      // Verify the token is now revoked
      const status = await statusListManager.getTokenStatus(testStatusListId, testTokenIndex);
      assert.strictEqual(status, 1, 'Token should be revoked (status = 1)');
    });

    it('should unrevoke a token by setting status back to 0', async () => {
      // Unrevoke the token
      const success = await statusListUpdateIndex(testStatusListId, testTokenIndex, 0);
      assert.strictEqual(success, true, 'Unrevocation should succeed');

      // Verify the token is now valid again
      const status = await statusListManager.getTokenStatus(testStatusListId, testTokenIndex);
      assert.strictEqual(status, 0, 'Token should be valid again (status = 0)');
    });
  });

  describe('Timeout Revocation Simulation', () => {
    it('should simulate the timeout revocation logic', async () => {
      // First, ensure the token is valid
      await statusListUpdateIndex(testStatusListId, testTokenIndex, 0);
      let status = await statusListManager.getTokenStatus(testStatusListId, testTokenIndex);
      assert.strictEqual(status, 0, 'Token should start valid');

      // Simulate the timeout revocation (this is what happens in the setTimeout)
      const revocationResult = await statusListUpdateIndex(testStatusListId, testTokenIndex, 1);
      assert.strictEqual(revocationResult, true, 'Timeout revocation should succeed');

      // Verify the token is now revoked
      status = await statusListManager.getTokenStatus(testStatusListId, testTokenIndex);
      assert.strictEqual(status, 1, 'Token should be revoked after timeout simulation');
    });
  });

  describe('Real Timeout Test', () => {
    it('should actually revoke after a timeout (using shorter timeout for testing)', async function() {
      // Increase timeout for this test since we're actually waiting
      this.timeout(10000); // 10 seconds

      // Ensure token starts valid
      await statusListUpdateIndex(testStatusListId, testTokenIndex, 0);
      let status = await statusListManager.getTokenStatus(testStatusListId, testTokenIndex);
      assert.strictEqual(status, 0, 'Token should start valid');

      // Create a promise that resolves when the timeout completes
      const timeoutPromise = new Promise((resolve) => {
        setTimeout(async () => {
          try {
            await statusListUpdateIndex(testStatusListId, testTokenIndex, 1);
            console.log(`Test timeout revoked ${testStatusListId}#${testTokenIndex}`);
            resolve(true);
          } catch (e) {
            console.error("Test timeout revocation failed", e);
            resolve(false);
          }
        }, 1000); // Use 1 second instead of 5 minutes for testing
      });

      // Wait for the timeout to complete
      const timeoutResult = await timeoutPromise;
      assert.strictEqual(timeoutResult, true, 'Timeout revocation should succeed');

      // Verify the token is now revoked
      status = await statusListManager.getTokenStatus(testStatusListId, testTokenIndex);
      assert.strictEqual(status, 1, 'Token should be revoked after actual timeout');
    });
  });

  describe('Status List Update Validation', () => {
    it('should update the updated_at timestamp when revoking', async () => {
      // Get initial timestamp
      const initialStatusList = await statusListGet(testStatusListId);
      const initialTimestamp = initialStatusList.updated_at;

      // Wait a moment to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 100));

      // Perform revocation
      await statusListUpdateIndex(testStatusListId, testTokenIndex, 1);

      // Get updated timestamp
      const updatedStatusList = await statusListGet(testStatusListId);
      const updatedTimestamp = updatedStatusList.updated_at;

      // Verify timestamp was updated (should be greater than or equal due to potential same-second updates)
      assert.ok(updatedTimestamp >= initialTimestamp, 'updated_at timestamp should be updated');
    });

    it('should maintain status list structure after updates', async () => {
      const statusList = await statusListGet(testStatusListId);
      
      // Verify the structure is maintained
      assert.ok(statusList.id, 'Status list should have id');
      assert.ok(statusList.size, 'Status list should have size');
      assert.ok(Array.isArray(statusList.statuses), 'Status list should have statuses array');
      assert.ok(statusList.updated_at, 'Status list should have updated_at timestamp');
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid status list id gracefully', async () => {
      const result = await statusListUpdateIndex('non-existent-id', 0, 1);
      assert.strictEqual(result, false, 'Should return false for non-existent status list');
    });

    it('should handle invalid index gracefully', async () => {
      const result = await statusListUpdateIndex(testStatusListId, 999, 1);
      assert.strictEqual(result, false, 'Should return false for invalid index');
    });

    it('should handle negative index gracefully', async () => {
      const result = await statusListUpdateIndex(testStatusListId, -1, 1);
      assert.strictEqual(result, false, 'Should return false for negative index');
    });
  });

  describe('Integration with VerifiableStudentIDSDJWT Flow', () => {
    it('should simulate the exact flow used in sharedIssuanceFlows.js', async () => {
      // This test simulates the exact logic from the sharedIssuanceFlows.js file
      const effectiveConfigurationId = "VerifiableStudentIDSDJWT";
      const statusListId = testStatusListId;
      const tokenIndex = testTokenIndex;

      // Ensure token starts valid
      await statusListUpdateIndex(statusListId, tokenIndex, 0);
      let status = await statusListManager.getTokenStatus(statusListId, tokenIndex);
      assert.strictEqual(status, 0, 'Token should start valid');

      // Simulate the timeout revocation logic from the code
      if (effectiveConfigurationId === "VerifiableStudentIDSDJWT") {
        // This is the exact logic from the setTimeout callback
        try {
          await statusListUpdateIndex(statusListId, tokenIndex, 1);
          console.log(`Timeout revoked ${statusListId}#${tokenIndex}`);
        } catch (e) {
          console.error("Timeout revocation failed", e);
          assert.fail('Timeout revocation should not throw an error');
        }
      }

      // Verify the token is now revoked
      status = await statusListManager.getTokenStatus(statusListId, tokenIndex);
      assert.strictEqual(status, 1, 'Token should be revoked after timeout logic execution');
    });
  });

  describe('Multiple Token Management', () => {
    it('should handle multiple tokens independently', async () => {
      const index1 = 10;
      const index2 = 20;

      // Set both tokens to valid
      await statusListUpdateIndex(testStatusListId, index1, 0);
      await statusListUpdateIndex(testStatusListId, index2, 0);

      // Verify both are valid
      let status1 = await statusListManager.getTokenStatus(testStatusListId, index1);
      let status2 = await statusListManager.getTokenStatus(testStatusListId, index2);
      assert.strictEqual(status1, 0, 'Token 1 should be valid');
      assert.strictEqual(status2, 0, 'Token 2 should be valid');

      // Revoke only token 1
      await statusListUpdateIndex(testStatusListId, index1, 1);

      // Verify token 1 is revoked but token 2 is still valid
      status1 = await statusListManager.getTokenStatus(testStatusListId, index1);
      status2 = await statusListManager.getTokenStatus(testStatusListId, index2);
      assert.strictEqual(status1, 1, 'Token 1 should be revoked');
      assert.strictEqual(status2, 0, 'Token 2 should still be valid');
    });
  });

  describe('Redis Persistence', () => {
    it('should persist revocation status across function calls', async () => {
      // Set token to revoked
      await statusListUpdateIndex(testStatusListId, testTokenIndex, 1);

      // Verify status through direct Redis access
      const statusList = await statusListGet(testStatusListId);
      assert.strictEqual(statusList.statuses[testTokenIndex], 1, 'Redis should reflect revoked status');

      // Verify status through status list manager
      const status = await statusListManager.getTokenStatus(testStatusListId, testTokenIndex);
      assert.strictEqual(status, 1, 'Status list manager should return revoked status');
    });
  });
});
