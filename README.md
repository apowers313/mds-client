# mds-client
[FIDO Metadata Service (MDS)](https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-metadata-service-v1.0-ps-20141208.html) Client

Retreives metadata table of contents (TOC) from MDS as well as any retreivable entries.

For more about FIDO, visit:
https://fidoalliance.org

## Installation

`npm install mds-client`

## API
``` js
var MDSC = require("mds-client");
var mdsClient = new MDSC(/* opt */);
mdsClient.fetchToc()
    .then(function (toc) {
        // do stuff with MDS TOC
        });

mdsClient.fetchEntries()
    .then(function (entries) {
        // do stuff with MDS entries
        });
```

* `constructor(opts)` - the constructor takes an options object argument with the following options:
    - `url` (default: https://mds.fidoalliance.org) - the URL for fetching the MDS TOC
    - `parallelFetchLimit` (default: 5) - the number of parallel requests when fetching metadata entries
* `fetchToc` - returns a Promise that resolves to a object containing the MDS TOC
* `fetchEntries` - returns a Promies that resolves to an Array of all metadata entries