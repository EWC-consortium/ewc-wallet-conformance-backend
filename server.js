// main file
import express from "express";
import router from "./routes/issue/preAuthSDjwRoutes.js";
import verifierRouter from "./routes/verify/verifierRoutes.js";
import metadataRouter from "./routes/metadataroutes.js";
import codeFlowRouter from "./routes/codeFlowJwtRoutes.js";
import codeFlowRouterSDJWT from "./routes/issue/codeFlowSdJwtRoutes.js";
import boardingPassRouter from "./routes/boardingPassRoutes.js";
import pidRouter from "./routes/pidroutes.js";
import paymentRouter from "./routes/paymentRoutes.js";
import passportRouter from "./routes/passportRoutes.js";
import didWebRouter from "./routes/didweb.js";
import educationalRouter from "./routes/educationalRoutes.js";
import sharedRouter from "./routes/issue/sharedIssuanceFlows.js";
import batchRouter from "./routes/batchRequestRoutes.js";
import receiptRouter from "./routes/receiptsRoutes.js";
import mdlRouter from "./routes/verify/mdlRoutes.js";
import loggingRouter from "./routes/loggingRoutes.js";
import vciStandardRouter from "./routes/issue/vciStandardRoutes.js";
import vpStandardRouter from "./routes/verify/vpStandardRoutes.js";
import vAttestationRouter from "./routes/verify/verifierAttestationRoutes.js";
import bodyParser from "body-parser"; // Body parser middleware
import {
  enableConsoleInterception,
  setSessionContext,
  clearSessionContext,
} from "./services/cacheServiceRedis.js";

import * as OpenApiValidator from "express-openapi-validator";

import path from "path";

// Path to your OpenAPI spec file (JSON or YAML)
const apiSpec = path.join(process.cwd(), "openapi.yaml");

const app = express();
const port = 3000;

// Enable console log interception globally
// This will capture all console.log/warn/error/info/debug calls and store them in cache
// when a session context is set via middleware
enableConsoleInterception();

// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ limit: "10mb", extended: true }));
// Middleware for post bodies
app.use(bodyParser.json({ limit: "10mb" }));
// Middleware for raw text bodies (needed for HAIP dc_api.jwt)
app.use(bodyParser.text({ limit: "10mb", type: "application/jwt" }));

// Global middleware to set session context for console log interception
// Extracts sessionId from multiple sources
app.use((req, res, next) => {
  // Try to extract sessionId from query params, request body, or URL params
  // Note: req.params is available after route matching, so we check all sources
  const sessionId =
    req.query.sessionId ||
    (req.body && req.body.sessionId) ||
    req.params.sessionId ||
    req.params.id || // Common pattern in routes
    null;

  if (sessionId) {
    req.sessionLoggingId = sessionId;
    res.locals = res.locals || {};
    res.locals.sessionLoggingId = sessionId;
    setSessionContext(sessionId);
    if (!res.locals.sessionLoggingCleanupBound) {
      const cleanup = () => {
        clearSessionContext();
        res.off("finish", cleanup);
        res.off("close", cleanup);
        res.locals.sessionLoggingCleanupBound = false;
      };
      res.on("finish", cleanup);
      res.on("close", cleanup);
      res.locals.sessionLoggingCleanupBound = true;
    }
  }
  next();
});

//Middleware to log all requests and responses for issuer endpoints
app.use((req, res, next) => {
  const startTime = Date.now();
  const sessionId =
    req.sessionLoggingId ||
    req.query.sessionId ||
    (req.body && req.body.sessionId) ||
    req.params.sessionId ||
    req.params.id ||
    "unknown";

  // Log incoming request
  console.log(`[${sessionId}] ---> ${req.method} ${req.url}`, {
    headers: req.headers,
    query: req.query,
    body: req.method !== 'GET' ? req.body : undefined,
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection.remoteAddress
  });

  // Store original response methods
  const originalSend = res.send;
  const originalJson = res.json;
  const originalEnd = res.end;

  // Override response methods to capture response data
  let responseBody = null;
  let responseStatus = null;

  res.send = function(data) {
    responseBody = data;
    responseStatus = res.statusCode;
    return originalSend.call(this, data);
  };

  res.json = function(data) {
    responseBody = JSON.stringify(data);
    responseStatus = res.statusCode;
    return originalJson.call(this, data);
  };

  res.end = function(data) {
    if (data && !responseBody) {
      responseBody = data;
    }

    const duration = Date.now() - startTime;

    // Log outgoing response
    console.log(`[${sessionId}] <--- ${req.method} ${req.url} ${responseStatus || res.statusCode} (${duration}ms)`, {
      status: responseStatus || res.statusCode,
      headers: res.getHeaders(),
      body: responseBody ? (responseBody.length > 1000 ? responseBody.substring(0, 1000) + '...' : responseBody) : undefined,
      contentLength: res.get('Content-Length'),
      duration: `${duration}ms`
    });

    return originalEnd.call(this, data);
  };

  next();
});

// const apiSpecPath = path.join(process.cwd(), "openapi.yml");
// app.use(
//   OpenApiValidator.middleware({
//     apiSpec: apiSpecPath,
//     validateRequests: false, // (default)
//     validateResponses: false, // false by default
//     // ignorePaths: [/^\/offer-code-sd-jwt$/, /^\/offer-no-code$/, /^\/offer-tx-code$/],
//   })
// );
app.use("/", router);
app.use("/", verifierRouter);
app.use("/", metadataRouter);
app.use("/", codeFlowRouter);
app.use("/", codeFlowRouterSDJWT);
app.use("/", pidRouter);
app.use("/", passportRouter);
app.use("/", educationalRouter);
app.use("/", boardingPassRouter);
app.use("/", didWebRouter);
app.use("/", paymentRouter);
app.use("/", sharedRouter);
app.use("/", batchRouter);
app.use("/", receiptRouter);
app.use("/mdl", mdlRouter);
app.use("/", loggingRouter);
app.use("/", vciStandardRouter);
app.use("/", vpStandardRouter);
app.use("/", vAttestationRouter);
// Error handler for validation errors
app.use((err, req, res, next) => {
  // Format error response
  res.status(err.status || 500).json({
    message: err.message,
    errors: err.errors,
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
