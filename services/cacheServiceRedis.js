import redis from "redis";

//
const VCI_CODE_FLOW_TIMEOUT = process.env.VCI_CODE_FLOW_TIMEOUT || 180;
const VCI_PRE_AUTH_TIMEOUT = process.env.VCI_PRE_AUTH_TIMEOUT || 180;
const VP_TIMEOUT = process.env.VP_TIMEOUT || 180;
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
    if (process.env.ALLOW_NO_REDIS === 'true' || process.env.NODE_ENV === 'test') {
      console.warn('Redis connection failed; continuing without Redis for tests.');
    } else {
      process.exit(1);
    }
  }
})();

// Add event listeners for Redis connection status
client.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

client.on('connect', () => {
  console.log('Redis Client Connected');
});

client.on('ready', () => {
  console.log('Redis Client Ready');
});

client.on('end', () => {
  console.log('Redis Client Connection Ended');
});

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
    // Check if Redis client is connected
    if (!client.isReady) {
      console.error("Redis client is not ready");
      throw new Error("Redis client is not ready");
    }
    
    const key = `pre-auth-sessions:${sessionKey}`;
    const ttlInSeconds = VCI_PRE_AUTH_TIMEOUT; // env, default: 3 minutes
    await client.setEx(key, ttlInSeconds, JSON.stringify(sessionValue)); // Set with expiration
  } catch (err) {
    console.error("Error storing session:", err);
    throw err; // Re-throw the error so calling code knows about the failure
  }
}
// Function to retrieve a pre-auth session from Redis
export async function getPreAuthSession(sessionKey) {
  try {
    // Check if Redis client is connected
    if (!client.isReady) {
      console.error("Redis client is not ready");
      throw new Error("Redis client is not ready");
    }
    
    const key = `pre-auth-sessions:${sessionKey}`;
    const result = await client.get(key);
    if (result) {
      return JSON.parse(result);
    } else {
      return null;
    }
  } catch (err) {
    console.error("Error retrieving session:", err);
    throw err; // Re-throw the error so calling code knows about the failure
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
    const ttlInSeconds = VCI_CODE_FLOW_TIMEOUT; // env, default: 3 minutes
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
    const ttlInSeconds = VP_TIMEOUT; // env, default: 3 minutes
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

// Function to atomically check and set last poll time for slow_down detection
// Returns true if poll is allowed (enough time has passed), false if polled too recently
export async function checkAndSetPollTime(preAuthorizedCode, minPollIntervalSeconds = 5) {
  try {
    if (!client.isReady) {
      console.error("Redis client is not ready");
      throw new Error("Redis client is not ready");
    }
    
    const key = `poll-times:${preAuthorizedCode}`;
    const now = Date.now();
    
    // Try to set the key only if it doesn't exist (NX flag)
    // Set expiration to the minimum poll interval
    const result = await client.set(key, now.toString(), {
      EX: minPollIntervalSeconds,
      NX: true // Only set if key doesn't exist
    });
    
    // If result is OK, the key was set successfully (poll allowed)
    // If result is null, the key already exists (polled too recently)
    return result === 'OK';
  } catch (err) {
    console.error("Error checking/setting poll time:", err);
    // On error, allow the poll to proceed (fail open)
    return true;
  }
}

// Function to clear poll tracking for a session
export async function clearPollTime(preAuthorizedCode) {
  try {
    if (!client.isReady) {
      return;
    }
    
    const key = `poll-times:${preAuthorizedCode}`;
    await client.del(key);
  } catch (err) {
    console.error("Error clearing poll time:", err);
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

// ============================================================================
// SESSION-BASED LOGGING FUNCTIONS
// ============================================================================

// Function to store logs for a specific session
export async function storeSessionLog(sessionId, logLevel, message, metadata = {}) {
  try {
    // Check if Redis client is connected
    if (!client.isReady) {
      console.error("Redis client is not ready");
      throw new Error("Redis client is not ready");
    }
    
    const key = `session-logs:${sessionId}`;
    const timestamp = new Date().toISOString();
    
    const logEntry = {
      timestamp,
      level: logLevel,
      message,
      metadata
    };
    
    // Get existing logs or initialize empty array
    const existingLogs = await client.get(key);
    let logs = existingLogs ? JSON.parse(existingLogs) : [];
    
    // Add new log entry
    logs.push(logEntry);
    
    // Keep only the last 100 log entries to prevent memory issues
    if (logs.length > 100) {
      logs = logs.slice(-100);
    }
    
    const ttlInSeconds = 1800; // 30 minutes
    await client.setEx(key, ttlInSeconds, JSON.stringify(logs));
    
    // Also log to console for immediate visibility
    console.log(`[${sessionId}] ${logLevel.toUpperCase()}: ${message}`, metadata);
  } catch (err) {
    console.error("Error storing session log:", err);
  }
}

// Function to retrieve all logs for a specific session
export async function getSessionLogs(sessionId) {
  try {
    // Check if Redis client is connected
    if (!client.isReady) {
      console.error("Redis client is not ready");
      throw new Error("Redis client is not ready");
    }
    
    const key = `session-logs:${sessionId}`;
    const result = await client.get(key);
    
    if (result) {
      return JSON.parse(result);
    } else {
      return [];
    }
  } catch (err) {
    console.error("Error retrieving session logs:", err);
    return [];
  }
}

// Function to clear logs for a specific session
export async function clearSessionLogs(sessionId) {
  try {
    // Check if Redis client is connected
    if (!client.isReady) {
      console.error("Redis client is not ready");
      throw new Error("Redis client is not ready");
    }
    
    const key = `session-logs:${sessionId}`;
    const result = await client.del(key);
    return result === 1;
  } catch (err) {
    console.error("Error clearing session logs:", err);
    return false;
  }
}

// Convenience functions for different log levels
export async function logInfo(sessionId, message, metadata = {}) {
  return await storeSessionLog(sessionId, 'info', message, metadata);
}

export async function logWarn(sessionId, message, metadata = {}) {
  return await storeSessionLog(sessionId, 'warn', message, metadata);
}

export async function logError(sessionId, message, metadata = {}) {
  return await storeSessionLog(sessionId, 'error', message, metadata);
}

export async function logDebug(sessionId, message, metadata = {}) {
  return await storeSessionLog(sessionId, 'debug', message, metadata);
}


//TODO evaluate this approach might be better
// ============================================================================
// CONSOLE LOG INTERCEPTION (OPTIONAL)
// ============================================================================
//
// To enable global console interception for all console.log/warn/error calls:
// 
// import { enableConsoleInterception } from './services/cacheServiceRedis.js';
// enableConsoleInterception();
//
// This will automatically capture all console logs when a session context is set.
// The session context is automatically managed by the x509Routes middleware.
//

// Store original console methods
const originalConsole = {
  log: console.log,
  warn: console.warn,
  error: console.error,
  info: console.info,
  debug: console.debug
};

// Session context storage for console interception
let currentSessionId = null;

// Function to set session context for console interception
export function setSessionContext(sessionId) {
  currentSessionId = sessionId;
}

// Function to clear session context
export function clearSessionContext() {
  currentSessionId = null;
}

// Function to enable console log interception
export function enableConsoleInterception() {
  console.log = (...args) => {
    originalConsole.log(...args);
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'info', message).catch(err => 
        originalConsole.error('Failed to store console.log:', err)
      );
    }
  };

  console.warn = (...args) => {
    originalConsole.warn(...args);
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'warn', message).catch(err => 
        originalConsole.error('Failed to store console.warn:', err)
      );
    }
  };

  console.error = (...args) => {
    originalConsole.error(...args);
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'error', message).catch(err => 
        originalConsole.error('Failed to store console.error:', err)
      );
    }
  };

  console.info = (...args) => {
    originalConsole.info(...args);
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'info', message).catch(err => 
        originalConsole.error('Failed to store console.info:', err)
      );
    }
  };

  console.debug = (...args) => {
    originalConsole.debug(...args);
    if (currentSessionId) {
      const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
      storeSessionLog(currentSessionId, 'debug', message).catch(err => 
        originalConsole.error('Failed to store console.debug:', err)
      );
    }
  };
}

// Function to disable console log interception
export function disableConsoleInterception() {
  console.log = originalConsole.log;
  console.warn = originalConsole.warn;
  console.error = originalConsole.error;
  console.info = originalConsole.info;
  console.debug = originalConsole.debug;
}
