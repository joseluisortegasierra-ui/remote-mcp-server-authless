import baseWorker, { JlosicNodeAgent } from "./index";
import { handleXRoutes, XAuthVault, type XEnv } from "./x";

export { JlosicNodeAgent, XAuthVault };

const baseFetch = (
	baseWorker as unknown as {
		fetch(request: Request, env: unknown, ctx: ExecutionContext): Promise<Response>;
	}
).fetch.bind(baseWorker);

export default {
	async fetch(request: Request, env: XEnv, ctx: ExecutionContext): Promise<Response> {
		const xResponse = await handleXRoutes(request, env);
		if (xResponse) return xResponse;
		return baseFetch(request, env, ctx);
	},
} satisfies ExportedHandler<XEnv>;
