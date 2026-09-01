"use strict";

require("fs").writeFileSync(process.env.LOAD_MARKER, "loaded\n");
module.exports = require("./transitive-cjs");
