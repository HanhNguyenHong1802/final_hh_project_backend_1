const express = require("express");
const cors = require("cors");
require("dotenv").config();
const cookieSession = require("cookie-session");
const app = express();

let corsOptions = {
  origin: "http://localhost:8081",
};

app.use(cors(corsOptions));

// parse requests of content-type - application/json
app.use(express.json());

// parse requests of content-type - application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));

app.use(
  cookieSession({
    name: "hani-session",
    secret: process.env.COOKIE_SECRET,
    httpOnly: true,
  })
);
const db = require("../models");

const Role = db.role;

db.mongoose
  .connect(process.env.ATLAS_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(async () => {
    console.log("Successfully connect to MongoDB.");
    await initial();
  })
  .catch((err) => {
    console.error("Connection error", err);
    process.exit();
  });

async function initial() {
  try {
    const count = await Role.estimatedDocumentCount();
    if (count === 0) {
      await Role.create({ name: "user" });
      await Role.create({ name: "moderator" });
      await Role.create({ name: "admin" });
      console.log("Roles initialized successfully");
    }
  } catch (error) {
    console.error("Error initializing roles:", error);
  }
}
require("../routes/auth.routes")(app);
require("../routes/user.routes")(app);

// set port, listen for requests
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});
