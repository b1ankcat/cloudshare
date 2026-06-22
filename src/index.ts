/**
 * Worker entry point. Wires the `fetch` handler to the router.
 */

import { handleRequest } from "./router";
import type { Env } from "./types";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return await handleRequest(request, env);
  },
} satisfies ExportedHandler<Env>;
