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


