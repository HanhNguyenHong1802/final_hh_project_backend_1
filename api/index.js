const authJwt = require("../middlewares/authjwt");
const verifySignUp = require("../middlewares/verifySignUp");

module.exports = {
  authJwt,
  verifySignUp,
};
