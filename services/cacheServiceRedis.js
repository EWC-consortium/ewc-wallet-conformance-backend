import redis from "redis";

//
const redis_url = process.env.REDIS ? process.env.REDIS : "localhost:6379";
// Create a Redis client
export const client = redis.createClient({
  url: `redis://${redis_url}`,
});

// Connect to Redis
(async () => {
  try {
    await client.connect();
    console.log("Connected to Redis");
  } catch (err) {
    console.error("Error connecting to Redis:", err);
    process.exit(1);
  }
})();

/*
pre-auth-sessions : {
  key: "12321-12312-12312" //session
  value :{
    result: {} //json,
    persona: "",
    accessToken: 
  }
}
*/

// Function to store a pre-auth session in Redis
export async function storePreAuthSession(sessionKey, sessionValue) {
  try {
    const key = `pre-auth-sessions:${sessionKey}`;
    const ttlInSeconds = 180; // 3 minutes
    await client.setEx(key, ttlInSeconds, JSON.stringify(sessionValue)); // Set with expiration
    console.log(`Session stored under key: ${key}`);
  } catch (err) {
    console.error("Error storing session:", err);
  }
}
// Function to retrieve a pre-auth session from Redis
export async function getPreAuthSession(sessionKey) {
  try {
    const key = `pre-auth-sessions:${sessionKey}`;
    const result = await client.get(key);
    if (result) {
      // console.log("Session retrieved:", JSON.parse(result));
      return JSON.parse(result);
    } else {
      console.log("Session not found for key:", key);
      return null;
    }
  } catch (err) {
    console.error("Error retrieving session:", err);
  }
}

// Function to get session key from an access token
export async function getSessionKeyFromAccessToken(accessToken) {
  try {
    const keys = await client.keys("pre-auth-sessions:*"); // Get all session keys
    for (const key of keys) {
      const session = await client.get(key);
      if (session) {
        const parsedSession = JSON.parse(session);
        if (parsedSession.accessToken === accessToken) {
          console.log(`Found session key for access token: ${accessToken}`);
          return key.replace("pre-auth-sessions:", ""); // Return the session key without the prefix
        }
      }
    }
    console.log("No session found for access token:", accessToken);
    return null;
  } catch (err) {
    console.error("Error retrieving session key for access token:", err);
  }
}

export async function storeCodeFlowSession(sessionKey, sessionValue) {
  try {
    const key = `code-flow-sessions:${sessionKey}`;
    const ttlInSeconds = 180; // 3 minutes
    await client.setEx(key, ttlInSeconds, JSON.stringify(sessionValue)); // Set with expiration
    console.log(`Session stored under key: ${key}`);
  } catch (err) {
    console.error("Error storing session:", err);
  }
}
// Function to retrieve a code-flow session from Redis
export async function getCodeFlowSession(sessionKey) {
  try {
    const key = `code-flow-sessions:${sessionKey}`;
    const result = await client.get(key);
    if (result) {
      // console.log("Session retrieved:", JSON.parse(result));
      return JSON.parse(result);
    } else {
      console.log("Session not found for key:", key);
      return null;
    }
  } catch (err) {
    console.error("Error retrieving session:", err);
  }
}

// Function to get session key from an access token
export async function getSessionKeyAuthCode(code) {
  try {
    const keys = await client.keys("code-flow-sessions:*"); // Get all session keys
    for (const key of keys) {
      const session = await client.get(key);
      if (session) {
        const parsedSession = JSON.parse(session);
        if (
          parsedSession.requests &&
          parsedSession.requests.sessionId == code
        ) {
          console.log(`Found session key for authorization code: ${code}`);
          return key.replace("code-flow-sessions:", ""); // Return the session key without the prefix
        }
      }
    }
    console.log("No session found for auth code:", code);
    return null;
  } catch (err) {
    console.error("Error retrieving session key for access token:", err);
  }
}

// Function to get session key from an access token
export async function getSessionAccessToken(token) {
  try {
    const keys = await client.keys("code-flow-sessions:*"); // Get all session keys
    for (const key of keys) {
      const session = await client.get(key);
      if (session) {
        const parsedSession = JSON.parse(session);
        if (
          parsedSession.requests &&
          parsedSession.requests.accessToken == token
        ) {
          console.log(`Found session key for access token: ${token}`);
          return key.replace("code-flow-sessions:", ""); // Return the session key without the prefix
        }
      }
    }
    console.log("No session found for auth code:", token);
    return null;
  } catch (err) {
    console.error("Error retrieving session key for access token:", err);
  }
}

export async function getDeferredSessionTransactionId(transaction_id) {
  try {
    const keys = await client.keys("code-flow-sessions:*"); // Get all session keys
    for (const key of keys) {
      const session = await client.get(key);
      if (session) {
        const parsedSession = JSON.parse(session);
        if (
          parsedSession.transaction_id &&
          parsedSession.transaction_id == transaction_id
        ) {
          console.log(
            `Found session key for transaction_id: ${transaction_id}`
          );
          return key.replace("code-flow-sessions:", ""); // Return the session key without the prefix
        }
      }
    }
    console.log("No session found for transaction_id:", transaction_id);
    return null;
  } catch (err) {
    console.error("Error retrieving session key for access token:", err);
  }
}

export async function storeVPSession(sessionKey, sessionValue) {
  try {
    const key = `vp-sessions:${sessionKey}`;
    const ttlInSeconds = 180; // 3 minutes
    await client.setEx(key, ttlInSeconds, JSON.stringify(sessionValue)); // Set with expiration
    console.log(`VP Session stored under key: ${key}`);
  } catch (err) {
    console.error("Error storing session:", err);
  }
}

export async function getVPSession(sessionKey) {
  try {
    const key = `vp-sessions:${sessionKey}`;
    const result = await client.get(key);
    if (result) {
      // console.log("VP Session retrieved:", JSON.parse(result));
      return JSON.parse(result);
    } else {
      console.log("Session not found for key:", key);
      return null;
    }
  } catch (err) {
    console.error("Error retrieving session:", err);
  }
}

// Function to store a nonce in Redis cache
export async function storeNonce(nonce, ttlInSeconds = 300) {
  try {
    const key = `nonces:${nonce}`;
    await client.setEx(key, ttlInSeconds, "1"); // Store with expiration, value doesn't matter for nonce
    console.log(`Nonce stored under key: ${key} with TTL: ${ttlInSeconds}s`);
  } catch (err) {
    console.error("Error storing nonce:", err);
  }
}

// Function to check if a nonce exists in Redis cache
export async function checkNonce(nonce) {
  try {
    const key = `nonces:${nonce}`;
    const result = await client.exists(key);
    const exists = result === 1;
    console.log(`Nonce ${nonce} ${exists ? 'found' : 'not found'} in cache`);
    return exists;
  } catch (err) {
    console.error("Error checking nonce:", err);
    return false;
  }
}

// Function to delete a nonce from Redis cache
export async function deleteNonce(nonce) {
  try {
    const key = `nonces:${nonce}`;
    const result = await client.del(key);
    const deleted = result === 1;
    console.log(`Nonce ${nonce} ${deleted ? 'deleted' : 'not found for deletion'} from cache`);
    return deleted;
  } catch (err) {
    console.error("Error deleting nonce:", err);
    return false;
  }
}

export function getPreCodeSessions() {
  return {
    sessions: sessions,
    results: issuanceResults,
    personas: personas,
    accessTokens: accesTokens,
  };
}

export function getAuthCodeSessions() {
  return {
    walletSessions: walletCodeSessions,
    sessions: issuerCodeSessions,
    requests: codeFlowRequests,
    results: codeFlowRequestsResults,
  };
}

export function getPushedAuthorizationRequests() {
  return pushedAuthorizationRequests;
}

export function getSessionsAuthorizationDetail() {
  return sessionsAuthorizationDetail;
}

export function getAuthCodeAuthorizationDetail() {
  return authCodeAuthorizationDetail;
}
