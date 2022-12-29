var http = require("http");
var https = require("https");
var express = require("express");
var bodyParser = require('body-parser');
var cors = require('cors');
var compression = require('compression');

var fs = require('fs');

var port = process.env.PORT || 9999;

var app = express();

app.use(compression());
app.use(cors());

app.use(function(req, res, next) {
  res.header("Cross-Origin-Embedder-Policy", "require-corp");
  res.header("Cross-Origin-Opener-Policy", "same-origin");
  next();
});

app.use(express.static(__dirname + "/../root.netfs/"));

var server = http.createServer(app);
server.listen(port, '0.0.0.0');
