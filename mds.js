var jwt = require ("jsonwebtoken");
var request = require ("request");
var b64 = require ("js-base64").Base64;
var rs = require("jsrsasign");
var inspect = require("util").inspect;

request('http://mds.fidoalliance.org', function (error, response, body) {
  if (!error && response.statusCode == 200) {
    console.log("MDS JWT:\n" + body);

    // TODO: implement x5u support
    // 1. verify that web origin matches URL for metadata download
    // 2. download and verify certificate chain, including checking for revocation
    // 3. throw error if verification fails

    // no npm JWT libraries seem to support x5c headers, so we have to get certs manually here...
    var header = JSON.parse(b64.decode(body.split(".")[0])); // TODO: will crash if not a valid JWT
    console.log ("Header:\n", header);
    var certChain = header.x5c;
    // console.log ("x5c:\n",certChain);
    var i, key, keys = [];
    for (i = 0; certChain && i < certChain.length; i++) {
        certChain[i] = "-----BEGIN CERTIFICATE-----\n" + certChain[i].replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----";

        // var cert = certChain[i];
        // console.log ("Cert " + i + ":\n", cert);
        // var c = new rs.X509();
        // c.readCertPEM(cert);
        // console.log ("Serial:", c.getSerialNumberHex());
        // key = rs.X509.getPublicKeyInfoPropOfCertPEM(cert);
        // console.log ("Key:", key);
        // console.log ("Crypto:", KJUR.crypto.OID.oidhex2name[key.algoid]);
        // console.log ("Crypto:", KJUR.crypto.OID.oidhex2name[key.algparam]);
        // console.log ("Key Hex:", key.keyhex);

        key = rs.X509.getPublicKeyFromCertPEM (certChain[i]);
        keys[i] = rs.KEYUTIL.getPEM (key);
        console.log ("x5c Public Key PEM " + i + ":\n" + keys[i]);
    }

    // TODO: validate cert chain
    // 1. validate expiration dates
    // 2. validate signatures
    // 3. check revocations

    var decoded = jwt.verify(body, keys[0], {algorithms: ["ES256"]});
    console.log ("Next Update:", decoded.nextUpdate);
    console.log ("Serial Number:", decoded.no);
    console.log ("Number of Entries:", decoded.entries.length);
    console.log (inspect(decoded, {depth: null}));
    var entry, entryList = [];
    for (i=0; i < decoded.entries.length; i++) {
    	entry = decoded.entries[i];
        entryList.push(entry.url);
    	
        console.log ("Downloading entry:",i);
    	request(entry.url, function (error, response, body) {
            var idx = entryList.indexOf(response.request.href);
    		if (!error && response.statusCode == 200) {
    			console.log ("Entry", idx);
    			console.log ("Entry URL: ", response.request.href);
    			console.log (JSON.stringify(b64.decode(body)));
                // console.log (body);

                // verify hash of body
                var entryHash = decoded.entries[idx].hash;
                var entryHashHex = rs.b64utohex(entryHash);
                var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
                md.updateString (body);
                var mdHex = md.digest();
                if (mdHex !== entryHashHex) {
                    throw "hash was incorrect for entry " + idx + ": " + response.request.href;
                }

                // TODO: compare hash against cached hash; if hash has changed and status report hasn't, there's a problem...
    		}
    	});
    }
  }
});