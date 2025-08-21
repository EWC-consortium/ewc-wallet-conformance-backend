import fs from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import zlib from "zlib";
import base64url from "base64url";
import * as jose from "jose";
import {
  statusListCreate,
  statusListGet,
  statusListGetAllIds,
  statusListDelete,
  statusListUpdateIndex,
} from "../services/cacheServiceRedis.js";

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

// Load private key for signing status list tokens
const privateKey = fs.readFileSync("./private-key.pem", "utf-8");

/**
 * Status List Token Manager
 * Manages the creation, storage, and retrieval of status list tokens
 */
class StatusListManager {
  constructor() {
    // In-memory cache for tokens only; source of truth is Redis
    this.statusListTokens = new Map();
  }

  async initialize() {
    // Ensure at least one default list exists
    const ids = await statusListGetAllIds();
    if (!ids || ids.length === 0) {
      await this.createStatusList(1000, 1);
    }
  }

  /**
   * Create a new status list with specified size
   * @param {number} size - Number of tokens in the status list
   * @param {number} bits - Bits per status (1, 2, 4, or 8)
   * @returns {Object} Status list object
   */
  async createStatusList(size = 1000, bits = 1, extra = {}) {
    if (![1, 2, 4, 8].includes(bits)) {
      throw new Error("Bits must be one of: 1, 2, 4, 8");
    }

    const id = uuidv4();
    const statusList = {
      id,
      size,
      bits,
      statuses: new Array(size).fill(0), // 0 = valid, 1 = revoked
      created_at: Math.floor(Date.now() / 1000),
      updated_at: Math.floor(Date.now() / 1000),
      ...extra
    };

    await statusListCreate(id, statusList);
    return statusList;
  }

  /**
   * Get a status list by ID
   * @param {string} id - Status list ID
   * @returns {Object|null} Status list object or null if not found
   */
  async getStatusList(id) {
    return await statusListGet(id);
  }

  /**
   * Update the status of a token in the status list
   * @param {string} statusListId - Status list ID
   * @param {number} index - Token index in the status list
   * @param {number} status - Status value (0 = valid, 1 = revoked)
   * @returns {boolean} Success status
   */
  async updateTokenStatus(statusListId, index, status) {
    const ok = await statusListUpdateIndex(statusListId, index, status);
    if (ok) this.statusListTokens.delete(statusListId);
    return ok;
  }

  /**
   * Get the status of a token in the status list
   * @param {string} statusListId - Status list ID
   * @param {number} index - Token index in the status list
   * @returns {number|null} Status value or null if not found
   */
  async getTokenStatus(statusListId, index) {
    const statusList = await statusListGet(statusListId);
    if (!statusList || index < 0 || index >= statusList.size) return null;
    return statusList.statuses[index];
  }

  /**
   * Convert status array to compressed bit array
   * @param {Array} statuses - Array of status values
   * @param {number} bits - Bits per status
   * @returns {Buffer} Compressed buffer
   */
  statusesToCompressedBuffer(statuses, bits) {
    // Convert statuses to bits
    const bitsArray = [];
    for (let i = 0; i < statuses.length; i++) {
      const status = statuses[i];
      for (let j = 0; j < bits; j++) {
        bitsArray.push((status >> j) & 1);
      }
    }

    // Convert bits to bytes
    const bytes = [];
    for (let i = 0; i < bitsArray.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8 && i + j < bitsArray.length; j++) {
        byte |= bitsArray[i + j] << j;
      }
      bytes.push(byte);
    }

    const buffer = Buffer.from(bytes);
    
    // Compress using zlib
    return zlib.deflateSync(buffer);
  }

  /**
   * Generate a Status List Token JWT
   * @param {string} statusListId - Status list ID
   * @returns {string} JWT token
   */
  async generateStatusListToken(statusListId) {
    const statusList = await statusListGet(statusListId);
    if (!statusList) throw new Error("Status list not found");

    // Check if we have a cached token
    if (this.statusListTokens.has(statusListId)) {
      const cached = this.statusListTokens.get(statusListId);
      if (cached.updated_at >= statusList.updated_at) {
        return cached.token;
      }
    }

    // Create compressed status list
    const compressedBuffer = this.statusesToCompressedBuffer(statusList.statuses, statusList.bits);
    const compressedBase64 = base64url.encode(compressedBuffer);

    // Create JWT payload
    const payload = {
      iss: serverURL,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 86400, // 24 hours
      status_list: {
        bits: statusList.bits,
        lst: compressedBase64
      }
    };

    // Sign the JWT
    const token = jwt.sign(payload, privateKey, { 
      algorithm: 'ES256',
      header: {
        typ: 'statuslist+jwt'
      }
    });

    // Cache the token
    this.statusListTokens.set(statusListId, {
      token,
      updated_at: statusList.updated_at
    });

    return token;
  }

  /**
   * Verify a Status List Token
   * @param {string} token - JWT token
   * @returns {Object|null} Decoded payload or null if invalid
   */
  verifyStatusListToken(token) {
    try {
      const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
      const decoded = jwt.verify(token, publicKeyPem, { 
        algorithms: ['ES256'],
        issuer: serverURL
      });
      return decoded;
    } catch (error) {
      console.error("Status list token verification failed:", error);
      return null;
    }
  }

  /**
   * Check if a token is revoked using a status list
   * @param {string} statusListToken - Status list JWT token
   * @param {number} tokenIndex - Index of the token to check
   * @returns {boolean} True if token is revoked, false if valid
   */
  isTokenRevoked(statusListToken, tokenIndex) {
    try {
      const decoded = this.verifyStatusListToken(statusListToken);
      if (!decoded || !decoded.status_list) {
        return false;
      }

      const { bits, lst } = decoded.status_list;
      
      // Decompress the status list
      const compressedBuffer = base64url.toBuffer(lst);
      const decompressedBuffer = zlib.inflateSync(compressedBuffer);
      
      // Convert to bits array
      const bitsArray = [];
      for (let i = 0; i < decompressedBuffer.length; i++) {
        const byte = decompressedBuffer[i];
        for (let bit = 0; bit < 8; bit++) {
          bitsArray.push((byte >> bit) & 1);
        }
      }

      // Calculate the bit index for the token
      const bitIndex = tokenIndex * bits;
      if (bitIndex >= bitsArray.length) {
        return false; // Index out of range, assume valid
      }

      // Extract the status value
      let status = 0;
      for (let i = 0; i < bits; i++) {
        if (bitIndex + i < bitsArray.length) {
          status |= bitsArray[bitIndex + i] << i;
        }
      }

      return status !== 0; // Non-zero means revoked
    } catch (error) {
      console.error("Error checking token revocation status:", error);
      return false;
    }
  }

  /**
   * Create a status reference for a credential
   * @param {string} statusListId - Status list ID
   * @param {number} index - Token index in the status list
   * @returns {Object} Status reference object
   */
  createStatusReference(statusListId, index) {
    return {
      status_list: {
        uri: `${serverURL}/status-list/${statusListId}`,
        idx: index
      }
    };
  }

  /**
   * Get all status lists (for admin purposes)
   * @returns {Array} Array of status list objects
   */
  async getAllStatusLists() {
    const ids = await statusListGetAllIds();
    const lists = [];
    for (const id of ids) {
      const sl = await statusListGet(id);
      if (sl) lists.push(sl);
    }
    return lists;
  }

  /**
   * Delete a status list
   * @param {string} id - Status list ID
   * @returns {boolean} Success status
   */
  async deleteStatusList(id) {
    const ok = await statusListDelete(id);
    if (ok) this.statusListTokens.delete(id);
    return ok;
  }
}

// Create a singleton instance
const statusListManager = new StatusListManager();
await statusListManager.initialize();

export default statusListManager;

// Export utility functions
export {
  StatusListManager
};
