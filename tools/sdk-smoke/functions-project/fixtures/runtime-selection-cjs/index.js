"use strict";

module.exports = require("./transitive-cjs");
require("fs").writeFileSync(process.env.LOAD_MARKER, "loaded\n");
