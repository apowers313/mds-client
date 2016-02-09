jwt = require ("jsonwebtoken");
request = require ("request");
b64 = require ("js-base64").Base64;

request('http://mds.fidoalliance.org', function (error, response, body) {
  if (!error && response.statusCode == 200) {
    console.log(body);

    // jwt.verify();
    var decoded = jwt.decode (body);
    console.log (decoded);
    console.log ("Next Update:", decoded.nextUpdate);
    console.log ("Serial Number:", decoded.no);
    console.log ("Number of Entries:", decoded.entries.length);
    var entry, i;
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