
const app = require("./app");

const host = process.env.SECUREFLOW_HOST ||
  (process.env.NODE_ENV === "production" ? "0.0.0.0" : "127.0.0.1");
const port = Number(process.env.PORT || 3000);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer from 1 to 65535.");
}

const server = app.listen(port, host, () => {
  console.log(`SecureFlow API listening on http://${host}:${port}`);
});

function shutdown() {
  server.close(() => {
    require("./db").close();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
