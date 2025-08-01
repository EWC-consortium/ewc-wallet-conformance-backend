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
import bodyParser from "body-parser"; // Body parser middleware

import * as OpenApiValidator from "express-openapi-validator";

import path from "path";

// Path to your OpenAPI spec file (JSON or YAML)
const apiSpec = path.join(process.cwd(), "openapi.yaml");

const app = express();
const port = 3000;

// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ limit: "10mb", extended: true }));
// Middleware for post bodies
app.use(bodyParser.json({ limit: "10mb" }));
// Middleware for raw text bodies (needed for HAIP dc_api.jwt)
app.use(bodyParser.text({ limit: "10mb", type: "application/jwt" }));
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
