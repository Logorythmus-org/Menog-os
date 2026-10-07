import { cliMain } from "../src/runner.js";
const rc = cliMain(process.argv.slice(2));
if (rc !== 0) process.exit(rc);
