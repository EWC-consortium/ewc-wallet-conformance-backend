import redis from "redis";

// Wallet-client dedicated Redis connection
// Configure via WALLET_REDIS env var (host:port) or default localhost:6379
const redisUrl = process.env.WALLET_REDIS ? process.env.WALLET_REDIS : "localhost:6379";

export const walletRedisClient = redis.createClient({ url: `redis://${redisUrl}` });

(async () => {
  try {
    await walletRedisClient.connect();
    console.log("Wallet client connected to Redis");
  } catch (err) {
    console.error("Wallet Redis connection error:", err);
  }
})();

walletRedisClient.on("error", (err) => {
  console.error("Wallet Redis Client Error:", err);
});

walletRedisClient.on("ready", () => {
  console.log("Wallet Redis Client Ready");
});

// Store credential and key-binding material under credential type (configurationId)
export async function storeWalletCredentialByType(configurationId, payload) {
  const key = `wallet:credentials:${configurationId}`;
  const ttlInSeconds = parseInt(process.env.WALLET_CREDENTIAL_TTL || "86400");
  await walletRedisClient.setEx(key, ttlInSeconds, JSON.stringify(payload));
}

export async function getWalletCredentialByType(configurationId) {
  const key = `wallet:credentials:${configurationId}`;
  const val = await walletRedisClient.get(key);
  return val ? JSON.parse(val) : null;
}

export async function listWalletCredentialTypes() {
  const keys = await walletRedisClient.keys("wallet:credentials:*");
  return keys.map((k) => k.replace(/^wallet:credentials:/, ""));
}

// Store logs under a specific sessionId key
export async function storeWalletLogs(sessionId, logs) {
  const key = `wallet:logs:${sessionId}`;
  const ttlInSeconds = parseInt(process.env.WALLET_LOGS_TTL || "3600"); // Default 1 hour
  
  // Clear existing list and add all logs
  await walletRedisClient.del(key);
  if (logs && logs.length > 0) {
    const logStrings = logs.map(log => JSON.stringify(log));
    await walletRedisClient.rPush(key, ...logStrings);
    await walletRedisClient.expire(key, ttlInSeconds);
  }
}

export async function getWalletLogs(sessionId) {
  const key = `wallet:logs:${sessionId}`;
  
  try {
    // Try to get as Redis list first
    const listLength = await walletRedisClient.lLen(key);
    if (listLength > 0) {
      const logEntries = await walletRedisClient.lRange(key, 0, -1);
      return logEntries.map(entry => JSON.parse(entry));
    }
    return null;
  } catch (error) {
    // If it's a WRONGTYPE error, the key contains old JSON format
    if (error.message && error.message.includes('WRONGTYPE')) {
      try {
        // Get the old JSON data
        const val = await walletRedisClient.get(key);
        if (val) {
          const oldLogs = JSON.parse(val);
          // Migrate to list format
          await walletRedisClient.del(key);
          if (oldLogs && oldLogs.length > 0) {
            const logStrings = oldLogs.map(log => JSON.stringify(log));
            await walletRedisClient.rPush(key, ...logStrings);
            const ttlInSeconds = parseInt(process.env.WALLET_LOGS_TTL || "3600");
            await walletRedisClient.expire(key, ttlInSeconds);
          }
          return oldLogs;
        }
      } catch (migrationError) {
        console.error("[cache] Failed to migrate logs:", migrationError);
        return null;
      }
    }
    console.error("[cache] Error getting logs:", error);
    return null;
  }
}

export async function appendWalletLog(sessionId, logEntry) {
  const key = `wallet:logs:${sessionId}`;
  const entryWithTimestamp = {
    ...logEntry,
    timestamp: new Date().toISOString()
  };
  
  try {
    // Use Redis list for atomic append operations
    await walletRedisClient.rPush(key, JSON.stringify(entryWithTimestamp));
    
    // Set TTL if this is the first entry
    const ttlInSeconds = parseInt(process.env.WALLET_LOGS_TTL || "3600");
    await walletRedisClient.expire(key, ttlInSeconds);
  } catch (error) {
    // If it's a WRONGTYPE error, migrate the old data first
    if (error.message && error.message.includes('WRONGTYPE')) {
      try {
        // Get the old JSON data and migrate
        const val = await walletRedisClient.get(key);
        await walletRedisClient.del(key);
        
        if (val) {
          const oldLogs = JSON.parse(val);
          if (oldLogs && oldLogs.length > 0) {
            const logStrings = oldLogs.map(log => JSON.stringify(log));
            await walletRedisClient.rPush(key, ...logStrings);
          }
        }
        
        // Now append the new entry
        await walletRedisClient.rPush(key, JSON.stringify(entryWithTimestamp));
        const ttlInSeconds = parseInt(process.env.WALLET_LOGS_TTL || "3600");
        await walletRedisClient.expire(key, ttlInSeconds);
      } catch (migrationError) {
        console.error("[cache] Failed to migrate logs during append:", migrationError);
      }
    } else {
      console.error("[cache] Error appending log:", error);
    }
  }
}


