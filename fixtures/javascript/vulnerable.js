const { exec } = require("node:child_process");

eval("console.log('unsafe')");
exec("echo " + process.env.USER_INPUT);
