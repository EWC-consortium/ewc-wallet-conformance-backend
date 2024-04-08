// main file
import express from "express";
import router from "./routes.js";
import verifierRouter from "./verifierRoutes.js";
import bodyParser from 'body-parser'; // Body parser middleware



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

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
  });