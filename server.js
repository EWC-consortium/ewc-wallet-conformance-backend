// main file
import express from "express";
import router from "./routes/routes.js";
import verifierRouter from "./routes/verifierRoutes.js";
import metadataRouter from "./routes/metadataroutes.js";
import codeFlowRouter from "./routes/codeFlowJwtRoutes.js";
import codeFlowRouterSDJWT from "./routes/codeFlowSdJwtRoutes.js";
import pidRouter from "./routes/pidroutes.js";
import passportRouter from "./routes/passportRoutes.js";
import educationalRouter from "./routes/educationalRoutes.js";
import bodyParser from "body-parser"; // Body parser middleware

const app = express();
const port = 3000;

// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));
// Middleware for post bodies
app.use(bodyParser.json());
//Middleware to log all requests to the server for debugging
app.use((req, res, next) => {
  console.log(`---> 
  ${req.method} ${req.url}`);
  next(); // Pass control to the next middleware function
});
app.use("/", router);
app.use("/", verifierRouter);
app.use("/", metadataRouter);
app.use("/", codeFlowRouter);
app.use("/", codeFlowRouterSDJWT);
app.use("/", pidRouter);
app.use("/", passportRouter);
app.use("/", educationalRouter);

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
