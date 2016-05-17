var _ = require("lodash");
var jwt = require("jsonwebtoken");
var request = require("request");
var b64url = require("js-base64").Base64;
var rs = require("jsrsasign"); // TODO: replace with node.js Crypto?
var inspect = require("util").inspect;
var async = require("async");

function MdsClient(opt) {
    opt = opt ? _.cloneDeep(opt) : {};
    var defaults = {
        url: "https://mds.fidoalliance.org",
        parallelFetchLimit: 5,
        log: console.log
    };
    _.defaultsDeep(opt, defaults);

    // TODO: verify options

    this.name = "MDS";
    this.opt = opt;
}

MdsClient.prototype.fetchToc = function() {
    return new Promise(function(resolve, reject) {
        request(this.opt.url, function(error, response, body) {
            if (!error && response.statusCode == 200) {

                // SECURITY TODO: implement x5u support
                // 1. verify that web origin matches URL for metadata download
                // 2. download and verify certificate chain, including checking for revocation
                // 3. throw error if verification fails

                // no npm JWT libraries seem to support x5c headers, so we have to get certs manually here...
                var jwtParts = body.split(".");
                if (jwtParts.length !== 3) {
                    return reject(new Error("Expected valid JWT from MDS"));
                }
                var header = JSON.parse(b64url.decode(jwtParts[0]));
                var certChain = header.x5c;
                var i, key, keys = [];
                for (i = 0; certChain && i < certChain.length; i++) {
                    certChain[i] = "-----BEGIN CERTIFICATE-----\n" + certChain[i].replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----";
                    key = rs.X509.getPublicKeyFromCertPEM(certChain[i]);
                    keys[i] = rs.KEYUTIL.getPEM(key);
                }

                // SECURITY TODO: validate cert chain
                // 1. validate expiration dates
                // 2. validate signatures
                // 3. check revocations

                var decoded = jwt.verify(body, keys[0], {
                    algorithms: ["ES256"]
                });
                console.log("Next Update:", decoded.nextUpdate);
                console.log("Serial Number:", decoded.no);
                console.log("Number of Entries:", decoded.entries.length);

                this.toc = decoded;
                return resolve(decoded);
            } else {
                return reject(new Error("Connection to MDS failed"));
            }
        }.bind(this));
    }.bind(this));
};

MdsClient.prototype.fetchEntries = function() {
    return new Promise(function(resolve, reject) {
        var entry, entryList = [];
        if (this.toc === undefined) {
            this.fetchToc();
        }
        var decoded = this.toc;

        var requestIterator = function(entry, cb) {
            entryList.push(entry.url);

            console.log("Downloading entry:", entry.url);
            request(entry.url, function(error, response, body) {
                var idx = entryList.indexOf(response.request.href);
                if (!error && response.statusCode == 200) {
                    var metadata = JSON.parse(b64url.decode(body));

                    // compare hash against cached hash; if hash has changed and status report hasn't, there's a problem...
                    var entryHash = decoded.entries[idx].hash;
                    var entryHashHex = rs.b64utohex(entryHash);
                    var md = new KJUR.crypto.MessageDigest({
                        alg: "sha256",
                        prov: "cryptojs"
                    });
                    md.updateString(body);
                    var mdHex = md.digest();
                    if (mdHex !== entryHashHex) {
                        return cb(new Error("Hash was incorrect for entry " + idx + ": " + response.request.href));
                    }
                    cb(null, metadata);
                } else {
                    return cb(new Error("Error fetching URL", response.request.href));
                }
            }.bind(this)); // TODO: simplify to have mapLimit() just call request?
        }.bind(this);

        async.mapLimit(decoded.entries, this.opt.parallelFetchLimit, requestIterator, function(err, results) {
            resolve(results);
        });
    }.bind(this));
};

// var mc = new MdsClient();
// mc.fetchToc()
//     .then(function(toc) {
//         return mc.fetchEntries();
//     }.bind(this))
//     .then(function(entries) {
//         // console.log (require("util").inspect(entries, {depth: null}));
//         console.log("Got ", entries.length, " entries.");
//     })
//     .catch(function(err) {
//         console.log("ERROR:", err);
//         throw (err);
//     });

module.exports = MdsClient;