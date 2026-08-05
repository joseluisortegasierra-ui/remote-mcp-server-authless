import { z } from "zod";

export interface XEnv {
	X_OAUTH: DurableObjectNamespace;
	X_CLIENT_ID?: string;
	X_CLIENT_SECRET?: string;
	X_REDIRECT_URI?: string;
	X_ACCOUNT_HANDLE?: string;
	X_POSTING_ENABLED?: string;
	JLOSIC_INGEST_TOKEN?: string;
}

type Tokens = {
	access_token: string;
	refresh_token?: string;
	token_type: string;
	scope?: string;
	expires_at: number;
	user_id?: string;
	username?: string;
};

type Pending = { state: string; verifier: string; created_at: number };
type Audit = {
	at: string;
	action: "connect" | "refresh" | "post" | "thread" | "error";
	ok: boolean;
	detail: string;
	post_ids?: string[];
};

const postSchema = z.object({
	text: z.string().min(1).max(280),
	reply_to_id: z.string().regex(/^\d+$/).optional(),
});

const threadSchema = z.object({
	posts: z.array(z.string().min(1).max(280)).min(2).max(25),
});

const SCOPES = "tweet.read tweet.write users.read offline.access";

function json(body: unknown, status = 200): Response {
	return Response.json(body, {
		status,
		headers: {
			"cache-control": "no-store",
			"x-content-type-options": "nosniff",
			"referrer-policy": "no-referrer",
		},
	});
}

function html(title: string, message: string, status = 200): Response {
	const esc = (value: string) =>
		value
			.replaceAll("&", "&amp;")
			.replaceAll("<", "&lt;")
			.replaceAll(">", "&gt;")
			.replaceAll('"', "&quot;")
			.replaceAll("'", "&#039;");
	return new Response(
		`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>body{margin:0;background:#090b10;color:#f6f7fb;font:17px/1.5 system-ui;display:grid;min-height:100vh;place-items:center}main{max-width:620px;padding:32px;border:1px solid #2b3445;border-radius:20px;background:#111722}h1{margin-top:0}p{color:#c7d0df}</style></head><body><main><h1>${esc(title)}</h1><p>${esc(message)}</p></main></body></html>`,
		{
			status,
			headers: {
				"content-type": "text/html; charset=utf-8",
				"cache-control": "no-store",
				"content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
				"x-content-type-options": "nosniff",
			},
		},
	);
}

function base64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function randomToken(size = 32): string {
	const bytes = new Uint8Array(size);
	crypto.getRandomValues(bytes);
	return base64Url(bytes);
}

async function challenge(verifier: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
	return base64Url(new Uint8Array(digest));
}

function authorized(request: Request, env: XEnv): boolean {
	return Boolean(
		env.JLOSIC_INGEST_TOKEN &&
			request.headers.get("authorization") === `Bearer ${env.JLOSIC_INGEST_TOKEN}`,
	);
}

function vault(env: XEnv): DurableObjectStub {
	return env.X_OAUTH.get(env.X_OAUTH.idFromName("jlosic-x-auth"));
}

async function callVault(env: XEnv, path: string, init?: RequestInit): Promise<Response> {
	return vault(env).fetch(`https://x-vault${path}`, init);
}

export class XAuthVault {
	constructor(
		private readonly state: DurableObjectState,
		private readonly env: XEnv,
	) {}

	private configured(): boolean {
		return Boolean(this.env.X_CLIENT_ID && this.env.X_CLIENT_SECRET && this.env.X_REDIRECT_URI);
	}

	private expectedHandle(): string {
		return (this.env.X_ACCOUNT_HANDLE ?? "JLOSICContexto").replace(/^@/, "").toLowerCase();
	}

	private basicAuth(): string {
		return `Basic ${btoa(`${this.env.X_CLIENT_ID}:${this.env.X_CLIENT_SECRET}`)}`;
	}

	private async audit(record: Audit): Promise<void> {
		const records = (await this.state.storage.get<Audit[]>("audit")) ?? [];
		records.unshift(record);
		await this.state.storage.put("audit", records.slice(0, 50));
	}

	private async exchange(params: URLSearchParams): Promise<Tokens> {
		const response = await fetch("https://api.x.com/2/oauth2/token", {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				authorization: this.basicAuth(),
			},
			body: params.toString(),
		});
		const payload = (await response.json()) as Record<string, unknown>;
		if (!response.ok || typeof payload.access_token !== "string") {
			throw new Error(
				`x_token_exchange_failed:${response.status}:${String(payload.error_description ?? payload.error ?? "unknown")}`,
			);
		}
		return {
			access_token: payload.access_token,
			refresh_token: typeof payload.refresh_token === "string" ? payload.refresh_token : undefined,
			token_type: String(payload.token_type ?? "bearer"),
			scope: typeof payload.scope === "string" ? payload.scope : undefined,
			expires_at: Date.now() + Number(payload.expires_in ?? 7200) * 1000,
		};
	}

	private async refresh(tokens: Tokens): Promise<Tokens> {
		if (!tokens.refresh_token) throw new Error("x_refresh_token_missing");
		const refreshed = await this.exchange(
			new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }),
		);
		const merged = {
			...refreshed,
			refresh_token: refreshed.refresh_token ?? tokens.refresh_token,
			user_id: tokens.user_id,
			username: tokens.username,
		};
		await this.state.storage.put("tokens", merged);
		await this.audit({ at: new Date().toISOString(), action: "refresh", ok: true, detail: "Token OAuth renovado." });
		return merged;
	}

	private async activeTokens(): Promise<Tokens> {
		const saved = await this.state.storage.get<Tokens>("tokens");
		if (!saved) throw new Error("x_not_connected");
		if (saved.expires_at > Date.now() + 60_000) return saved;
		return this.refresh(saved);
	}

	private async xFetch(path: string, init?: RequestInit): Promise<Response> {
		let tokens = await this.activeTokens();
		const send = () => {
			const headers = new Headers(init?.headers);
			headers.set("authorization", `Bearer ${tokens.access_token}`);
			return fetch(`https://api.x.com${path}`, { ...init, headers });
		};
		let response = await send();
		if (response.status === 401 && tokens.refresh_token) {
			tokens = await this.refresh(tokens);
			response = await send();
		}
		return response;
	}

	private async publish(text: string, replyTo?: string): Promise<string> {
		const body: Record<string, unknown> = { text };
		if (replyTo) body.reply = { in_reply_to_tweet_id: replyTo };
		const response = await this.xFetch("/2/tweets", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		});
		const payload = (await response.json()) as Record<string, unknown>;
		const data = payload.data as Record<string, unknown> | undefined;
		if (!response.ok || typeof data?.id !== "string") {
			throw new Error(`x_post_failed:${response.status}:${JSON.stringify(payload).slice(0, 300)}`);
		}
		return data.id;
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		try {
			if (request.method === "GET" && url.pathname === "/start") {
				if (!this.configured()) return json({ error: "x_secrets_not_configured" }, 503);
				const state = randomToken(32);
				const verifier = randomToken(48);
				await this.state.storage.put(`pending:${state}`, {
					state,
					verifier,
					created_at: Date.now(),
				} satisfies Pending);
				const auth = new URL("https://x.com/i/oauth2/authorize");
				auth.search = new URLSearchParams({
					response_type: "code",
					client_id: this.env.X_CLIENT_ID!,
					redirect_uri: this.env.X_REDIRECT_URI!,
					scope: SCOPES,
					state,
					code_challenge: await challenge(verifier),
					code_challenge_method: "S256",
				}).toString();
				return json({ authorization_url: auth.toString() });
			}

			if (request.method === "POST" && url.pathname === "/callback") {
				if (!this.configured()) return json({ error: "x_secrets_not_configured" }, 503);
				const input = (await request.json()) as { code?: string; state?: string };
				if (!input.code || !input.state) return json({ error: "missing_code_or_state" }, 400);
				const pending = await this.state.storage.get<Pending>(`pending:${input.state}`);
				if (!pending || pending.state !== input.state || Date.now() - pending.created_at > 10 * 60_000) {
					return json({ error: "invalid_or_expired_state" }, 400);
				}
				await this.state.storage.delete(`pending:${input.state}`);
				const tokens = await this.exchange(
					new URLSearchParams({
						grant_type: "authorization_code",
						code: input.code,
						redirect_uri: this.env.X_REDIRECT_URI!,
						code_verifier: pending.verifier,
					}),
				);
				const meResponse = await fetch("https://api.x.com/2/users/me", {
					headers: { authorization: `Bearer ${tokens.access_token}` },
				});
				const mePayload = (await meResponse.json()) as Record<string, unknown>;
				const me = mePayload.data as Record<string, unknown> | undefined;
				const username = String(me?.username ?? "");
				if (!meResponse.ok || !username || username.toLowerCase() !== this.expectedHandle()) {
					await this.audit({
						at: new Date().toISOString(),
						action: "error",
						ok: false,
						detail: `Cuenta rechazada: ${username || "desconocida"}.`,
					});
					return json({ error: "unexpected_x_account", username }, 403);
				}
				await this.state.storage.put("tokens", {
					...tokens,
					user_id: String(me?.id ?? ""),
					username,
				} satisfies Tokens);
				await this.audit({ at: new Date().toISOString(), action: "connect", ok: true, detail: `Conectada @${username}.` });
				return json({ connected: true, username });
			}

			if (request.method === "GET" && url.pathname === "/status") {
				const tokens = await this.state.storage.get<Tokens>("tokens");
				const audit = (await this.state.storage.get<Audit[]>("audit")) ?? [];
				return json({
					configured: this.configured(),
					connected: Boolean(tokens),
					username: tokens?.username ?? null,
					posting_enabled: this.env.X_POSTING_ENABLED === "true",
					last_event: audit[0] ?? null,
				});
			}

			if (request.method === "POST" && url.pathname === "/post") {
				if (this.env.X_POSTING_ENABLED !== "true") return json({ error: "x_posting_disabled" }, 423);
				const payload = postSchema.parse(await request.json());
				const id = await this.publish(payload.text, payload.reply_to_id);
				await this.audit({ at: new Date().toISOString(), action: "post", ok: true, detail: "Publicación creada.", post_ids: [id] });
				return json({ published: true, id }, 201);
			}

			if (request.method === "POST" && url.pathname === "/thread") {
				if (this.env.X_POSTING_ENABLED !== "true") return json({ error: "x_posting_disabled" }, 423);
				const payload = threadSchema.parse(await request.json());
				const ids: string[] = [];
				let replyTo: string | undefined;
				for (const text of payload.posts) {
					const id = await this.publish(text, replyTo);
					ids.push(id);
					replyTo = id;
				}
				await this.audit({
					at: new Date().toISOString(),
					action: "thread",
					ok: true,
					detail: `Hilo de ${ids.length} publicaciones creado.`,
					post_ids: ids,
				});
				return json({ published: true, ids }, 201);
			}

			return json({ error: "not_found" }, 404);
		} catch (error) {
			const detail = error instanceof Error ? error.message : "unknown_error";
			await this.audit({ at: new Date().toISOString(), action: "error", ok: false, detail: detail.slice(0, 300) });
			if (error instanceof z.ZodError) {
				return json({ error: "invalid_payload", issues: (error as { issues?: unknown }).issues }, 400);
			}
			return json({ error: "x_bridge_error", detail }, 500);
		}
	}
}

export async function handleXRoutes(request: Request, env: XEnv): Promise<Response | null> {
	const url = new URL(request.url);
	if (request.method === "GET" && url.pathname === "/x/connect") {
		const response = await callVault(env, "/start");
		const payload = (await response.json()) as { authorization_url?: string; error?: string };
		if (!response.ok || !payload.authorization_url) {
			return html("Conexión no disponible", payload.error ?? "No se pudo iniciar OAuth.", response.status);
		}
		return Response.redirect(payload.authorization_url, 302);
	}
	if (request.method === "GET" && url.pathname === "/x/callback") {
		const code = url.searchParams.get("code");
		const state = url.searchParams.get("state");
		const error = url.searchParams.get("error");
		if (error) return html("Autorización cancelada", `X devolvió: ${error}.`, 400);
		if (!code || !state) return html("Autorización incompleta", "Faltan el código o el estado de OAuth.", 400);
		const response = await callVault(env, "/callback", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ code, state }),
		});
		const payload = (await response.json()) as { connected?: boolean; username?: string; error?: string };
		return response.ok && payload.connected
			? html("X conectado", `@${payload.username} quedó autorizada. Ya puedes cerrar esta página.`)
			: html("No se pudo conectar X", payload.error ?? "Error desconocido.", response.status);
	}
	if (request.method === "GET" && url.pathname === "/x/status") {
		return callVault(env, "/status");
	}
	if (request.method === "POST" && (url.pathname === "/api/x/post" || url.pathname === "/api/x/thread")) {
		if (!authorized(request, env)) {
			return json({ error: env.JLOSIC_INGEST_TOKEN ? "unauthorized" : "publisher_token_not_configured" }, env.JLOSIC_INGEST_TOKEN ? 401 : 503);
		}
		const target = url.pathname.endsWith("/thread") ? "/thread" : "/post";
		return callVault(env, target, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: await request.text(),
		});
	}
	return null;
}
