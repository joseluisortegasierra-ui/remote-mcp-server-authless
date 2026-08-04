import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";

type NodeId =
	| "juridico"
	| "medios_ingresos"
	| "economia_limpieza"
	| "editorial"
	| "corpus_infraestructura";

type NodeStatus =
	| "sleeping"
	| "queued"
	| "ready_for_connector"
	| "executed"
	| "blocked";

interface JlosicEnv {
	JLOSIC_NODES: DurableObjectNamespace;
	JLOSIC_INGEST_TOKEN?: string;
	SERVICE_LABEL?: string;
	MESH_VERSION?: string;
	DEPLOYMENT_CHANNEL?: string;
	DEPLOYMENT_MARKER?: string;
}

interface SignalInput {
	node_id: NodeId;
	source: string;
	external_id: string;
	version: string;
	summary: string;
	priority: number;
	sensitivity: "public" | "sanitized";
	observed_at: string;
}

interface StoredSignal extends SignalInput {
	id: string;
	received_at: string;
}

interface OutcomeInput {
	state: "executed" | "prepared" | "blocked" | "waiting";
	action: string;
	evidence: string;
	result: string;
	blocker: string;
	next_action: string;
	completed_at: string;
}

interface StoredNodeState {
	node_id: NodeId;
	status: NodeStatus;
	queue_depth: number;
	received_signals: number;
	prepared_signals: number;
	completed_actions: number;
	duplicate_signals: number;
	no_signal_pulses: number;
	last_check_at: string | null;
	last_signal_at: string | null;
	last_action: string;
	last_evidence: string;
	last_result: string;
	blocker: string;
	next_action: string;
}

const NODE_CARDS = [
	{
		id: "juridico",
		label: "Jurídico · Seguridad Social e IMV",
		wake_on: ["respuesta", "notificación", "plazo", "documento nuevo"],
		minute: 3,
	},
	{
		id: "medios_ingresos",
		label: "Medios, ingresos y difusión",
		wake_on: ["respuesta humana", "rebote", "solicitud", "oportunidad"],
		minute: 11,
	},
	{
		id: "economia_limpieza",
		label: "Economía y limpieza digital",
		wake_on: ["cargo", "respuesta", "incidencia", "cambio verificable"],
		minute: 19,
	},
	{
		id: "editorial",
		label: "Libro · La deuda de contexto",
		wake_on: ["unidad nueva", "vacío documentado", "revisión solicitada"],
		minute: 27,
	},
	{
		id: "corpus_infraestructura",
		label: "Corpus, Drive y vigilancia técnica",
		wake_on: ["cambio de fuente", "commit", "fallo", "vacío de contexto"],
		minute: 35,
	},
] as const satisfies ReadonlyArray<{
	id: NodeId;
	label: string;
	wake_on: readonly string[];
	minute: number;
}>;

const NODE_IDS = NODE_CARDS.map((node) => node.id);

const signalSchema = z.object({
	node_id: z.enum(NODE_IDS as [NodeId, ...NodeId[]]),
	source: z.string().min(2).max(120),
	external_id: z.string().min(1).max(200),
	version: z.string().min(1).max(120),
	summary: z.string().min(3).max(1000),
	priority: z.number().int().min(0).max(100).default(50),
	sensitivity: z.enum(["public", "sanitized"]),
	observed_at: z.string().datetime({ offset: true }),
});

const outcomeSchema = z.object({
	state: z.enum(["executed", "prepared", "blocked", "waiting"]),
	action: z.string().max(300).default(""),
	evidence: z.string().max(300).default(""),
	result: z.string().max(500).default(""),
	blocker: z.string().max(300).default(""),
	next_action: z.string().max(300).default(""),
	completed_at: z.string().datetime({ offset: true }),
});

function isNodeId(value: string): value is NodeId {
	return NODE_IDS.includes(value as NodeId);
}

function nodeCard(nodeId: NodeId) {
	return NODE_CARDS.find((node) => node.id === nodeId) ?? NODE_CARDS[4];
}

function initialNodeState(nodeId: NodeId): StoredNodeState {
	return {
		node_id: nodeId,
		status: "sleeping",
		queue_depth: 0,
		received_signals: 0,
		prepared_signals: 0,
		completed_actions: 0,
		duplicate_signals: 0,
		no_signal_pulses: 0,
		last_check_at: null,
		last_signal_at: null,
		last_action: "Sin acción registrada.",
		last_evidence: "Sin prueba registrada.",
		last_result: "Nodo dormido hasta recibir una señal material.",
		blocker: "",
		next_action: "Esperar una señal deduplicada de su propia línea.",
	};
}

function mappedStatus(state: OutcomeInput["state"]): NodeStatus {
	if (state === "executed") return "executed";
	if (state === "blocked") return "blocked";
	if (state === "prepared") return "ready_for_connector";
	return "sleeping";
}

function jsonResponse(body: unknown, status = 200, cacheSeconds = 0): Response {
	return Response.json(body, {
		status,
		headers: {
			"cache-control": cacheSeconds > 0 ? `public, max-age=${cacheSeconds}` : "no-store",
			"access-control-allow-origin": "*",
			"x-content-type-options": "nosniff",
			"referrer-policy": "no-referrer",
		},
	});
}

function authorized(request: Request, env: JlosicEnv): boolean {
	return Boolean(
		env.JLOSIC_INGEST_TOKEN &&
			request.headers.get("authorization") === `Bearer ${env.JLOSIC_INGEST_TOKEN}`,
	);
}

async function signalId(input: SignalInput): Promise<string> {
	const raw = [input.node_id, input.source, input.external_id, input.version].join("\u001f");
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
	return [...new Uint8Array(digest)]
		.map((value) => value.toString(16).padStart(2, "0"))
		.join("");
}

function nextPulseAt(nodeId: NodeId): number {
	const minute = nodeCard(nodeId).minute;
	const next = new Date();
	next.setUTCSeconds(0, 0);
	if (next.getUTCMinutes() >= minute) next.setUTCHours(next.getUTCHours() + 1);
	next.setUTCMinutes(minute);
	return next.getTime();
}

export class JlosicNodeAgent {
	constructor(
		private readonly state: DurableObjectState,
		private readonly env: JlosicEnv,
	) {}

	private async ensureNode(request?: Request): Promise<NodeId> {
		const saved = await this.state.storage.get<NodeId>("node_id");
		const header = request?.headers.get("x-jlosic-node") ?? "";
		const nodeId = saved ?? (isNodeId(header) ? header : "corpus_infraestructura");
		if (!saved) {
			await this.state.storage.put({
				node_id: nodeId,
				node_state: initialNodeState(nodeId),
				queue: [] satisfies StoredSignal[],
			});
		}
		if ((await this.state.storage.getAlarm()) === null) {
			await this.state.storage.setAlarm(nextPulseAt(nodeId));
		}
		return nodeId;
	}

	private async readState(nodeId: NodeId): Promise<StoredNodeState> {
		return (
			(await this.state.storage.get<StoredNodeState>("node_state")) ??
			initialNodeState(nodeId)
		);
	}

	private async runPulse(nodeId: NodeId): Promise<{ prepared: number; node_id: NodeId }> {
		const now = new Date().toISOString();
		const queue = (await this.state.storage.get<StoredSignal[]>("queue")) ?? [];
		const current = await this.readState(nodeId);
		if (queue.length === 0) {
			const updated: StoredNodeState = {
				...current,
				status: "sleeping",
				queue_depth: 0,
				no_signal_pulses: current.no_signal_pulses + 1,
				last_check_at: now,
				last_result: "Sin novedad material; parada sin llamada a modelo.",
				next_action: "Esperar una señal propia; los demás nodos continúan independientes.",
			};
			await this.state.storage.put("node_state", updated);
			return { prepared: 0, node_id: nodeId };
		}

		queue.sort((a, b) => b.priority - a.priority || a.received_at.localeCompare(b.received_at));
		const batch = queue.splice(0, 3);
		const updated: StoredNodeState = {
			...current,
			status: "ready_for_connector",
			queue_depth: queue.length,
			prepared_signals: current.prepared_signals + batch.length,
			last_check_at: now,
			last_action: `Preparadas ${batch.length} señal(es) sanitizada(s).`,
			last_evidence: batch.map((signal) => signal.id.slice(0, 12)).join(", "),
			last_result: "Contexto mínimo listo; no se ha enviado ni publicado nada.",
			blocker: "Falta un conector privado autorizado para ejecutar fuera de Cloudflare.",
			next_action: "El conector de la línea debe ejecutar y devolver prueba verificable.",
		};
		await this.state.storage.put({ queue, node_state: updated });
		return { prepared: batch.length, node_id: nodeId };
	}

	async alarm(): Promise<void> {
		const nodeId = await this.ensureNode();
		await this.runPulse(nodeId);
		await this.state.storage.setAlarm(nextPulseAt(nodeId));
	}

	async fetch(request: Request): Promise<Response> {
		const nodeId = await this.ensureNode(request);
		const url = new URL(request.url);

		if (request.method === "GET" && url.pathname === "/status") {
			const state = await this.readState(nodeId);
			const card = nodeCard(nodeId);
			return jsonResponse({
				...state,
				label: card.label,
				wake_on: card.wake_on,
				pulse: `minuto ${card.minute} de cada hora UTC; se detiene sin señal`,
				independent: true,
			});
		}

		if (request.method === "POST" && url.pathname === "/signal") {
			const payload = signalSchema.parse(await request.json());
			if (payload.node_id !== nodeId) return jsonResponse({ error: "node_mismatch" }, 409);
			const id = await signalId(payload);
			const seenKey = `seen:${id}`;
			const current = await this.readState(nodeId);
			if (await this.state.storage.get<boolean>(seenKey)) {
				await this.state.storage.put("node_state", {
					...current,
					duplicate_signals: current.duplicate_signals + 1,
				});
				return jsonResponse({ accepted: false, duplicate: true, id });
			}

			const queue = (await this.state.storage.get<StoredSignal[]>("queue")) ?? [];
			if (queue.length >= 100) return jsonResponse({ error: "node_queue_full" }, 429);
			const receivedAt = new Date().toISOString();
			queue.push({ ...payload, id, received_at: receivedAt });
			const updated: StoredNodeState = {
				...current,
				status: "queued",
				queue_depth: queue.length,
				received_signals: current.received_signals + 1,
				last_signal_at: receivedAt,
				last_result: "Señal recibida directamente; ningún coordinador la reasignó.",
				blocker: "",
				next_action: "Preparar la unidad en el pulso propio del nodo.",
			};
			await this.state.storage.put({ [seenKey]: true, queue, node_state: updated });
			return jsonResponse({ accepted: true, duplicate: false, id }, 202);
		}

		if (request.method === "POST" && url.pathname === "/pulse") {
			return jsonResponse(await this.runPulse(nodeId));
		}

		if (request.method === "POST" && url.pathname === "/outcome") {
			const payload = outcomeSchema.parse(await request.json());
			const current = await this.readState(nodeId);
			const updated: StoredNodeState = {
				...current,
				status: mappedStatus(payload.state),
				completed_actions:
					current.completed_actions + (payload.state === "executed" ? 1 : 0),
				last_check_at: payload.completed_at,
				last_action: payload.action || "Sin acción material.",
				last_evidence: payload.evidence || "Sin prueba registrada.",
				last_result: payload.result || "Sin resultado material.",
				blocker: payload.blocker,
				next_action: payload.next_action || "Esperar una nueva señal.",
			};
			await this.state.storage.put("node_state", updated);
			return jsonResponse({ recorded: true, node_id: nodeId }, 202);
		}

		return jsonResponse({ error: "not_found" }, 404);
	}
}

const PUBLIC_CARD = {
	name: "JLOSIC Direct Mesh",
	version: "2.0.2",
	status: "operational_when_deployed",
	topology: "five_direct_independent_nodes",
	central_dispatcher: false,
	shared_chain: false,
	model_calls: "none_in_cloudflare_runtime",
	endpoints: {
		panel: "/",
		health: "/health",
		mesh: "/mesh",
		capabilities: "/.well-known/jlosic-capabilities.json",
		mcp: "/mcp",
		private_signal: "/api/signals",
		private_node_signal: "/api/nodes/{node_id}/signals",
		private_node_outcome: "/api/nodes/{node_id}/outcomes",
	},
	nodes: NODE_CARDS.map(({ minute: _minute, ...node }) => node),
	privacy: {
		public_payloads: "estado técnico y metadatos mínimos",
		private_payloads: "solo señales sanitizadas y autenticadas",
		rejected: ["expedientes completos", "datos médicos o financieros", "correos completos", "credenciales"],
	},
	limits: [
		"Cloudflare no accede por sí solo a Gmail, Drive ni modelos",
		"ningún token de administración se entrega a los nodos",
		"los envíos, pagos y publicaciones siguen fuera del runtime público",
	],
} as const;

function getNodeStub(env: JlosicEnv, nodeId: NodeId): DurableObjectStub {
	return env.JLOSIC_NODES.get(env.JLOSIC_NODES.idFromName(nodeId));
}

async function callNode(
	env: JlosicEnv,
	nodeId: NodeId,
	path: string,
	init?: RequestInit,
): Promise<Response> {
	const headers = new Headers(init?.headers);
	headers.set("x-jlosic-node", nodeId);
	return getNodeStub(env, nodeId).fetch(`https://jlosic-node${path}`, { ...init, headers });
}

async function allNodeStatuses(env: JlosicEnv): Promise<unknown[]> {
	return Promise.all(
		NODE_IDS.map(async (nodeId) => {
			const response = await callNode(env, nodeId, "/status");
			return response.json();
		}),
	);
}

function textContent(value: unknown) {
	return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

function createServer() {
	const server = new McpServer({ name: PUBLIC_CARD.name, version: PUBLIC_CARD.version });
	server.registerTool(
		"mesh_status",
		{ description: "Devuelve el contrato público de la malla directa JLOSIC.", inputSchema: z.object({}) },
		async () => textContent(PUBLIC_CARD),
	);
	server.registerTool(
		"list_public_nodes",
		{ description: "Lista los cinco nodos independientes.", inputSchema: z.object({}) },
		async () => textContent({ nodes: PUBLIC_CARD.nodes }),
	);
	server.registerTool(
		"explain_topology",
		{ description: "Explica la topología sin despachador central.", inputSchema: z.object({}) },
		async () =>
			textContent({
				routing: "direct_to_named_node",
				shared_chain: false,
				failure_isolation: "one_node_failure_does_not_block_peers",
				common_state: "read_only_aggregation",
				no_signal: "stop_without_model_call",
			}),
	);
	return server;
}

const mcpHandler = createMcpHandler(createServer);

function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#039;");
}

function panelHtml(nodes: unknown[], version: string): string {
	const cards = nodes
		.map((raw) => {
			const node = raw as Record<string, unknown>;
			return `<article><h2>${escapeHtml(String(node.label ?? node.node_id))}</h2><strong>${escapeHtml(String(node.status))}</strong><p>${escapeHtml(String(node.last_result))}</p><small>Cola ${escapeHtml(String(node.queue_depth))} · recibidas ${escapeHtml(String(node.received_signals))} · preparadas ${escapeHtml(String(node.prepared_signals))} · ejecutadas ${escapeHtml(String(node.completed_actions))}</small></article>`;
		})
		.join("");
	return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="60"><title>Ahora · JLOSIC</title><style>body{margin:0;background:#080b12;color:#f6f7fb;font:16px/1.45 system-ui}main{width:min(1000px,calc(100% - 24px));margin:auto;padding:28px 0}h1{font-size:clamp(34px,8vw,64px);margin:0}.lead{color:#aeb9cd}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}article{border:1px solid #273248;border-radius:18px;background:#111723;padding:18px}strong{color:#6ee7c7}small{color:#aeb9cd}@media(max-width:720px){.grid{grid-template-columns:1fr}}</style></head><body><main><h1>Ahora · JLOSIC</h1><p class="lead">Cinco nodos directos. Ningún nodo elige, autoriza ni bloquea a otro.</p><p>Versión ${escapeHtml(version)} · 5 nodos · 0 cadenas centrales</p><section class="grid">${cards}</section><p class="lead">Rutas: /health · /mesh · /.well-known/jlosic-capabilities.json · /mcp</p></main></body></html>`;
}

async function privateNodeRoute(
	request: Request,
	env: JlosicEnv,
	url: URL,
): Promise<Response | null> {
	const match = url.pathname.match(
		/^\/api\/nodes\/(juridico|medios_ingresos|economia_limpieza|editorial|corpus_infraestructura)\/(signals|pulse|outcomes)$/,
	);
	if (!match) return null;
	if (!authorized(request, env)) {
		return jsonResponse(
			{ error: env.JLOSIC_INGEST_TOKEN ? "unauthorized" : "private_ingest_not_configured" },
			env.JLOSIC_INGEST_TOKEN ? 401 : 503,
		);
	}
	if (request.method !== "POST") return jsonResponse({ error: "method_not_allowed" }, 405);

	const nodeId = match[1] as NodeId;
	const action = match[2];
	const target = action === "signals" ? "/signal" : action === "outcomes" ? "/outcome" : "/pulse";
	const response = await callNode(env, nodeId, target, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: action === "pulse" ? undefined : await request.text(),
	});
	return new Response(response.body, response);
}

export default {
	async fetch(request: Request, env: JlosicEnv, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		if (url.hostname === "www.jlos.uk") {
			url.hostname = "jlos.uk";
			return Response.redirect(url.toString(), 308);
		}
		if (request.method === "OPTIONS") {
			return new Response(null, {
				status: 204,
				headers: {
					"access-control-allow-origin": "*",
					"access-control-allow-methods": "GET, POST, OPTIONS",
					"access-control-allow-headers": "authorization, content-type, mcp-session-id",
				},
			});
		}
		if (request.method === "GET" && url.pathname === "/health") {
			return jsonResponse(
				{
					ok: true,
					service: env.SERVICE_LABEL ?? PUBLIC_CARD.name,
					version: env.MESH_VERSION ?? PUBLIC_CARD.version,
					runtime: "worker_reachable",
					topology: PUBLIC_CARD.topology,
					central_dispatcher: false,
					shared_chain: false,
					deployment_channel: env.DEPLOYMENT_CHANNEL ?? "unknown",
					deployment_marker: env.DEPLOYMENT_MARKER ?? "unknown",
					private_ingest_configured: Boolean(env.JLOSIC_INGEST_TOKEN),
					now: new Date().toISOString(),
				},
				200,
				15,
			);
		}
		if (request.method === "GET" && url.pathname === "/mesh") {
			return jsonResponse(
				{
					status: "operational",
					topology: PUBLIC_CARD.topology,
					central_dispatcher: false,
					shared_chain: false,
					private_ingest_configured: Boolean(env.JLOSIC_INGEST_TOKEN),
					nodes: await allNodeStatuses(env),
					updated_at: new Date().toISOString(),
				},
				200,
				15,
			);
		}
		if (request.method === "GET" && url.pathname === "/.well-known/jlosic-capabilities.json") {
			return jsonResponse(PUBLIC_CARD, 200, 300);
		}
		if (url.pathname === "/mcp" || url.pathname.startsWith("/mcp/")) {
			return mcpHandler(request, env, ctx);
		}
		const privateRoute = await privateNodeRoute(request, env, url);
		if (privateRoute) return privateRoute;
		if (request.method === "POST" && url.pathname === "/api/signals") {
			if (!authorized(request, env)) {
				return jsonResponse(
					{ error: env.JLOSIC_INGEST_TOKEN ? "unauthorized" : "private_ingest_not_configured" },
					env.JLOSIC_INGEST_TOKEN ? 401 : 503,
				);
			}
			try {
				const payload = signalSchema.parse(await request.json());
				const response = await callNode(env, payload.node_id, "/signal", {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify(payload),
				});
				return new Response(response.body, response);
			} catch (error) {
				if (error instanceof z.ZodError) return jsonResponse({ error: "invalid_signal" }, 400);
				throw error;
			}
		}
		if (request.method === "GET" && url.pathname === "/") {
			return new Response(
				panelHtml(await allNodeStatuses(env), env.MESH_VERSION ?? PUBLIC_CARD.version),
				{
					headers: {
						"content-type": "text/html; charset=utf-8",
						"cache-control": "no-store",
						"content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
						"x-content-type-options": "nosniff",
					},
				},
			);
		}
		return jsonResponse({ error: "not_found" }, 404);
	},
} satisfies ExportedHandler<JlosicEnv>;
