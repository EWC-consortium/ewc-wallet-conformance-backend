import express from "express";
import {
  getSessionLogs,
  clearSessionLogs,
  logInfo,
} from "../services/cacheServiceRedis.js";
import { createErrorResponse } from "../utils/routeUtils.js";

const loggingRouter = express.Router();

/**
 * SESSION LOGGING API ENDPOINTS
 * 
 * This router provides endpoints to manage session-based logs stored in Redis.
 * All logs are associated with session IDs and have a 30-minute TTL.
 * 
 * Available endpoints:
 * - GET /logs/:sessionId - Retrieve all logs for a session
 * - DELETE /logs/:sessionId - Clear logs for a session
 */

/**
 * Get logs for a specific session
 */
loggingRouter.get("/logs/:sessionId", async (req, res) => {
  try {
    const sessionId = req.params.sessionId;
    await logInfo(sessionId, "Retrieving session logs", { endpoint: "/logs/:sessionId" });
    
    const logs = await getSessionLogs(sessionId);
    res.json({
      sessionId,
      logs,
      count: logs.length
    });
  } catch (error) {
    const errorResponse = createErrorResponse(error, "GET /logs/:sessionId");
    res.status(500).json(errorResponse);
  }
});

/**
 * Clear logs for a specific session
 */
loggingRouter.delete("/logs/:sessionId", async (req, res) => {
  try {
    const sessionId = req.params.sessionId;
    await logInfo(sessionId, "Clearing session logs", { endpoint: "DELETE /logs/:sessionId" });
    
    const cleared = await clearSessionLogs(sessionId);
    res.json({
      sessionId,
      cleared,
      message: cleared ? "Logs cleared successfully" : "No logs found to clear"
    });
  } catch (error) {
    const errorResponse = createErrorResponse(error, "DELETE /logs/:sessionId");
    res.status(500).json(errorResponse);
  }
});

/**
 * Get logs for multiple sessions (optional utility endpoint)
 */
loggingRouter.post("/logs/batch", async (req, res) => {
  try {
    const { sessionIds } = req.body;
    
    if (!Array.isArray(sessionIds) || sessionIds.length === 0) {
      return res.status(400).json({ 
        error: "sessionIds must be a non-empty array" 
      });
    }
    
    const results = {};
    for (const sessionId of sessionIds) {
      try {
        const logs = await getSessionLogs(sessionId);
        results[sessionId] = {
          logs,
          count: logs.length
        };
      } catch (error) {
        results[sessionId] = {
          error: error.message,
          logs: [],
          count: 0
        };
      }
    }
    
    res.json({
      results,
      totalSessions: sessionIds.length
    });
  } catch (error) {
    const errorResponse = createErrorResponse(error, "POST /logs/batch");
    res.status(500).json(errorResponse);
  }
});

export default loggingRouter;
