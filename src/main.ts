import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { parseConfig } from "./config.js";
import { createRuntime } from "./runtime.js";
import { startHttpServer } from "./http.js";

export async function start(env = process.env) {
  const input: unknown = env.DOTCORD_CONFIG ? JSON.parse(await readFile(env.DOTCORD_CONFIG,"utf8")) : {};
  const config = parseConfig(input,env.DOTCORD_NETWORK_ENABLED === "1");
  const runtime = await createRuntime(config,undefined,code => { if (/^[a-z_]+$/.test(code)) console.info(code); });
  try {
    const http = await startHttpServer(runtime);
    let closing: Promise<void> | undefined;
    return {runtime,http,stop:() => closing ??= (async () => { await runtime.stop(); await http.stop(); })()};
  } catch (error) { await runtime.stop(); throw error; }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const app = await start();
    console.info(app.runtime.config.enabled ? "dotcord_started" : "dotcord_disabled");
    for (const signal of ["SIGINT","SIGTERM"] as const) process.once(signal,() => { void app.stop().then(() => process.exit(0),() => process.exit(1)); });
  } catch { console.error("dotcord_start_failed"); process.exitCode=1; }
}
