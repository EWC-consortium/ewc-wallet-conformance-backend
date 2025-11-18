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
// Extracts sessionId from query params or request body
// Note: URL params (req.params) are handled by route-specific middleware
app.use((req, res, next) => {
  // Try to extract sessionId from query params or request body
  // req.params won't be available until after route matching, so route-specific
  // middleware handles those cases (see didRoutes, x509Routes, etc.)
  const sessionId = 
    req.query.sessionId || 
    (req.body && req.body.sessionId) ||
    null;
  
  if (sessionId) {
    setSessionContext(sessionId);
    // Clear context when response finishes
    res.on('finish', () => {
      clearSessionContext();
    });
    res.on('close', () => {
      clearSessionContext();
    });
  }
  next();
});

//Middleware to log all requests to the server for debugging
app.use((req, res, next) => {
  console.log(`---> 
  ${req.method} ${req.url}`);
  next(); // Pass control to the next middleware function
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
