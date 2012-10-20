//
// Allows two connections to meet and communicate
var https = require("https");
var fs = require("fs");

var LISTEN_PORT = Number(process.argv[2]);

var options = {
    key: fs.readFileSync("etc/server-key.pem"),
    cert: fs.readFileSync("etc/server-cert.pem"),

    requestCert: true,
    rejectUnauthorized: true,

    ca: [ fs.readFileSync("etc/server-cert.pem") ]
};

// Agents that are allowed to rendezvous
TRUSTED_AGENTS = {
    "human-agent": {
        sources: { 
            "127.0.0.1": true
        }
    },
    "cylon-agent": {
        sources: {
            "127.0.0.1": true
        }
    }
};

// Active meetings
MEETS = {};

function httpError(res, msg){
    res.writeHead(404);
    res.end(msg);
};

var entrance = https.createServer(options, function(req, res){
    // Get the secret from the request header
    var agent = req.headers["user-agent"];
    var secret = req.headers["secret"];
    var source = req.connection.remoteAddress;

    var callsign = agent+"@"+source;

    if(!secret || !TRUSTED_AGENTS[agent] ||
            !TRUSTED_AGENTS[agent].sources[source]){
        console.log("Access denied to "+callsign);
        httpError(res, "Nothing to see here!");
        req.connection.destroy();
        return;
    }

    req.on("close", function(){
        console.log(callsign+" exited");
    });

    console.log(callsign+" entered");
    var a = MEETS[secret];
    if(a){
        console.log(a.callsign+" meeting with "+callsign);
        a.conn.pipe(req.connection);
        req.connection.pipe(a.conn);
    }else{
        console.log(callsign+" waiting");
        MEETS[secret] = {
            callsign: callsign,
            conn: req.connection
        }
    }
});
entrance.listen(LISTEN_PORT, function(){
    console.log("Security guard listening on port "+LISTEN_PORT);
});
