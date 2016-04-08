var jwt = require ("jsonwebtoken");
var request = require ("request");
var b64 = require ("js-base64").Base64;
var rs = require("jsrsasign");

request('http://mds.fidoalliance.org', function (error, response, body) {
  if (!error && response.statusCode == 200) {
    console.log("MDS JWT:\n" + body);

    // no npm JWT libraries seem to support x5c headers, so we have to get certs manually here...
    var header = JSON.parse(b64.decode(body.split(".")[0])); // TODO: will crash if not a valid JWT
    // console.log ("Header:\n", header);
    var certChain = header.x5c;
    // console.log ("x5c:\n",certChain);
    var i, key, keys = [];
    for (i = 0; certChain && i < certChain.length; i++) {
        // var cert = "-----BEGIN CERTIFICATE-----\n" + certChain[i].replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----";
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

    var decoded = jwt.verify(body, keys[0], {algorithms: ["ES256"]});
    console.log (decoded);
    console.log ("Next Update:", decoded.nextUpdate);
    console.log ("Serial Number:", decoded.no);
    console.log ("Number of Entries:", decoded.entries.length);
    var entry;
    for (i=0; i < decoded.entries.length; i++) {
    	entry = decoded.entries[i];
    	

    	request(entry.url, function (error, response, body) {
    		if (!error && response.statusCode == 200) {
    			console.log ("Entry", i);
    			console.log ("Entry URL: ", entry.url);
    			console.log (b64.decode(body));
    		}
    	});
    }
  }
});