import express from "express";
import bodyParser from "body-parser";
const server = express();

server.use(bodyParser.json());

export default server;
