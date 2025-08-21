import express from "express";
import statusListManager from "../utils/statusListUtils.js";

const statusListRouter = express.Router();

/**
 * GET /status-list/:id
 * Serves a Status List Token JWT
 * According to the IETF draft, this endpoint should return a JWT with status_list claim
 */
statusListRouter.get("/status-list/:id", async (req, res) => {
  try {
    const statusListId = req.params.id;
    
    // Check if status list exists
    const statusList = await statusListManager.getStatusList(statusListId);
    if (!statusList) {
      return res.status(404).json({
        error: "status_list_not_found",
        error_description: "Status list not found"
      });
    }

    // Generate status list token
    const statusListToken = await statusListManager.generateStatusListToken(statusListId);
    
    // Set appropriate headers
    res.set({
      'Content-Type': 'application/statuslist+jwt',
      'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Accept, Authorization'
    });

    // Return the JWT token
    res.send(statusListToken);
  } catch (error) {
    console.error("Error serving status list:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Failed to generate status list token"
    });
  }
});

/**
 * GET /status-list/:id/info
 * Returns information about a status list (for admin/debugging purposes)
 */
statusListRouter.get("/status-list/:id/info", async (req, res) => {
  try {
    const statusListId = req.params.id;
    const statusList = await statusListManager.getStatusList(statusListId);
    
    if (!statusList) {
      return res.status(404).json({
        error: "status_list_not_found",
        error_description: "Status list not found"
      });
    }

    // Return status list info (excluding the actual statuses array for privacy)
    res.json({
      id: statusList.id,
      size: statusList.size,
      bits: statusList.bits,
      created_at: statusList.created_at,
      updated_at: statusList.updated_at,
      revoked_count: statusList.statuses.filter(s => s !== 0).length,
      valid_count: statusList.statuses.filter(s => s === 0).length
    });
  } catch (error) {
    console.error("Error getting status list info:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Failed to get status list information"
    });
  }
});

/**
 * POST /status-list
 * Create a new status list (admin endpoint)
 */
statusListRouter.post("/status-list", async (req, res) => {
  try {
    const { size = 1000, bits = 1 } = req.body;
    
    if (![1, 2, 4, 8].includes(bits)) {
      return res.status(400).json({
        error: "invalid_bits",
        error_description: "Bits must be one of: 1, 2, 4, 8"
      });
    }

    if (size <= 0 || size > 100000) {
      return res.status(400).json({
        error: "invalid_size",
        error_description: "Size must be between 1 and 100000"
      });
    }

    const statusList = await statusListManager.createStatusList(size, bits);
    
    res.status(201).json({
      id: statusList.id,
      size: statusList.size,
      bits: statusList.bits,
      created_at: statusList.created_at,
      status_list_uri: `${req.protocol}://${req.get('host')}/status-list/${statusList.id}`
    });
  } catch (error) {
    console.error("Error creating status list:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Failed to create status list"
    });
  }
});

/**
 * PUT /status-list/:id/revoke/:index
 * Revoke a token at a specific index (admin endpoint)
 */
statusListRouter.put("/status-list/:id/revoke/:index", async (req, res) => {
  try {
    const statusListId = req.params.id;
    const index = parseInt(req.params.index);
    
    if (isNaN(index) || index < 0) {
      return res.status(400).json({
        error: "invalid_index",
        error_description: "Index must be a non-negative integer"
      });
    }

    const success = await statusListManager.updateTokenStatus(statusListId, index, 1); // 1 = revoked
    
    if (!success) {
      return res.status(404).json({
        error: "status_list_not_found",
        error_description: "Status list not found or index out of range"
      });
    }

    res.json({
      success: true,
      message: `Token at index ${index} has been revoked`,
      status_list_uri: `${req.protocol}://${req.get('host')}/status-list/${statusListId}`
    });
  } catch (error) {
    console.error("Error revoking token:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Failed to revoke token"
    });
  }
});

/**
 * PUT /status-list/:id/unrevoke/:index
 * Unrevoke a token at a specific index (admin endpoint)
 */
statusListRouter.put("/status-list/:id/unrevoke/:index", async (req, res) => {
  try {
    const statusListId = req.params.id;
    const index = parseInt(req.params.index);
    
    if (isNaN(index) || index < 0) {
      return res.status(400).json({
        error: "invalid_index",
        error_description: "Index must be a non-negative integer"
      });
    }

    const success = await statusListManager.updateTokenStatus(statusListId, index, 0); // 0 = valid
    
    if (!success) {
      return res.status(404).json({
        error: "status_list_not_found",
        error_description: "Status list not found or index out of range"
      });
    }

    res.json({
      success: true,
      message: `Token at index ${index} has been unrevoked`,
      status_list_uri: `${req.protocol}://${req.get('host')}/status-list/${statusListId}`
    });
  } catch (error) {
    console.error("Error unrevoking token:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Failed to unrevoke token"
    });
  }
});

/**
 * GET /status-list/:id/status/:index
 * Check the status of a specific token (admin endpoint)
 */
statusListRouter.get("/status-list/:id/status/:index", async (req, res) => {
  try {
    const statusListId = req.params.id;
    const index = parseInt(req.params.index);
    
    if (isNaN(index) || index < 0) {
      return res.status(400).json({
        error: "invalid_index",
        error_description: "Index must be a non-negative integer"
      });
    }

    const status = await statusListManager.getTokenStatus(statusListId, index);
    
    if (status === null) {
      return res.status(404).json({
        error: "status_list_not_found",
        error_description: "Status list not found or index out of range"
      });
    }

    res.json({
      index,
      status: status === 0 ? "valid" : "revoked",
      status_value: status
    });
  } catch (error) {
    console.error("Error checking token status:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Failed to check token status"
    });
  }
});

/**
 * GET /status-lists
 * Get all status lists (admin endpoint)
 */
statusListRouter.get("/status-lists", async (req, res) => {
  try {
    const statusLists = await statusListManager.getAllStatusLists();
    
    const statusListInfos = statusLists.map(statusList => ({
      id: statusList.id,
      size: statusList.size,
      bits: statusList.bits,
      created_at: statusList.created_at,
      updated_at: statusList.updated_at,
      revoked_count: statusList.statuses.filter(s => s !== 0).length,
      valid_count: statusList.statuses.filter(s => s === 0).length,
      status_list_uri: `${req.protocol}://${req.get('host')}/status-list/${statusList.id}`
    }));

    res.json(statusListInfos);
  } catch (error) {
    console.error("Error getting all status lists:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Failed to get status lists"
    });
  }
});

/**
 * DELETE /status-list/:id
 * Delete a status list (admin endpoint)
 */
statusListRouter.delete("/status-list/:id", async (req, res) => {
  try {
    const statusListId = req.params.id;
    const success = await statusListManager.deleteStatusList(statusListId);
    
    if (!success) {
      return res.status(404).json({
        error: "status_list_not_found",
        error_description: "Status list not found"
      });
    }

    res.json({
      success: true,
      message: "Status list deleted successfully"
    });
  } catch (error) {
    console.error("Error deleting status list:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Failed to delete status list"
    });
  }
});

/**
 * POST /status-list/verify
 * Verify a status list token and check if a specific token is revoked
 */
statusListRouter.post("/status-list/verify", async (req, res) => {
  try {
    const { status_list_token, token_index } = req.body;
    
    if (!status_list_token || token_index === undefined) {
      return res.status(400).json({
        error: "missing_parameters",
        error_description: "status_list_token and token_index are required"
      });
    }

    const isRevoked = statusListManager.isTokenRevoked(status_list_token, token_index);
    
    res.json({
      token_index,
      is_revoked: isRevoked,
      status: isRevoked ? "revoked" : "valid"
    });
  } catch (error) {
    console.error("Error verifying status list token:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Failed to verify status list token"
    });
  }
});

export default statusListRouter;
