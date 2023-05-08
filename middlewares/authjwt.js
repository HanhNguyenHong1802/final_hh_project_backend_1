const jwt = require("jsonwebtoken");
const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;

const verifyToken = (req, res, next) => {
  let token = req.headers["x-access-token"];
  if (!token) {
    return res.status(400).send({ message: "No token provided!" });
  }
  jwt.verify(token, config.secret, (err, encoded) => {
    if (err) {
      return res.status(401).send({ message: "Unauthorized!" });
    }
    req.userId = decoded.id;
    next();
  });
};

const isAdmin = (req, res, next) => {
  User.findById(req.userId)
    .then((user) => {
      if (!user) {
        return res.status(404).send({ message: "User not found." });
      }

      Role.find({ _id: { $in: user.roles } })
        .then((roles) => {
          if (!roles || roles.length === 0) {
            return res.status(403).send({ message: "Require Admin Role!" });
          }

          for (const element of roles) {
            if (element.name === "admin") {
              next();
              return;
            }
          }

          res.status(403).send({ message: "Require Admin Role!" });
        })
        .catch((err) => {
          res.status(500).send({ message: err });
        });
    })
    .catch((err) => {
      res.status(500).send({ message: err });
    });
};

const isModerator = (req, res, next) => {
  User.findById(req.userId)
    .then((user) => {
      if (!user) {
        return res.status(404).send({ message: "User not found." });
      }

      Role.find({ _id: { $in: user.roles } })
        .then((roles) => {
          if (!roles || roles.length === 0) {
            return res.status(403).send({ message: "Require Moderator Role!" });
          }

          for (const element of roles) {
            if (element.name === "moderator") {
              next();
              return;
            }
          }

          res.status(403).send({ message: "Require Moderator Role!" });
        })
        .catch((err) => {
          res.status(500).send({ message: err });
        });
    })
    .catch((err) => {
      res.status(500).send({ message: err });
    });
};

const authJwt = {
  verifyToken,
  isAdmin,
  isModerator,
};
module.exports = authJwt;
