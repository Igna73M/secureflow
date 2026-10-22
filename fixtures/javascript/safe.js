const { execFile } = require("node:child_process");

execFile("/usr/bin/printf", ["%s", "hello"]);
console.log("safe");
