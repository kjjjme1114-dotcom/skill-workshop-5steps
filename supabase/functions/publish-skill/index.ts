const APP_ORIGIN = "https://kjjjme1114-dotcom.github.io";
const MAX_BODY_BYTES = 32_000;

const corsHeaders = {
  "Access-Control-Allow-Origin": APP_ORIGIN,
  "Access-Control-Allow-Headers": "apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

function respond(body: Record<string, string>, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

function requiredEnv(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing required function secret: ${name}`);
  return value;
}

function keyFromEnvDictionary(name: string, prefix: "sb_publishable_" | "sb_secret_"): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing Supabase-provided key dictionary: ${name}`);

  let dictionary: unknown;
  try {
    dictionary = JSON.parse(value);
  } catch {
    throw new Error(`Invalid Supabase-provided key dictionary: ${name}`);
  }
  if (!dictionary || typeof dictionary !== "object" || Array.isArray(dictionary)) {
    throw new Error(`Invalid Supabase-provided key dictionary: ${name}`);
  }

  const key = Object.values(dictionary).find(
    (candidate): candidate is string =>
      typeof candidate === "string" && candidate.startsWith(prefix),
  );
  if (!key) throw new Error(`No ${prefix} key found in Supabase-provided dictionary: ${name}`);
  return key;
}

async function readLimitedBody(request: Request): Promise<string> {
  const contentLength = Number(request.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    throw new RangeError("Request body too large");
  }

  const reader = request.body?.getReader();
  if (!reader) throw new SyntaxError("Missing request body");
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new RangeError("Request body too large");
    }
    chunks.push(value);
  }

  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(body);
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

async function hashAddress(address: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(address)),
  );
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (request) => {
  const origin = request.headers.get("origin");
  if (origin !== APP_ORIGIN) return respond({ error: "origin_not_allowed" }, 403);
  if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  if (request.method !== "POST") return respond({ error: "method_not_allowed" }, 405);

  try {
    const supabaseUrl = requiredEnv("SUPABASE_URL").replace(/\/+$/, "");
    const serverKey = keyFromEnvDictionary("SUPABASE_SECRET_KEYS", "sb_secret_");
    const publishableKey = keyFromEnvDictionary("SUPABASE_PUBLISHABLE_KEYS", "sb_publishable_");
    const rateLimitSecret = requiredEnv("RATE_LIMIT_SECRET");
    if (request.headers.get("apikey") !== publishableKey) {
      return respond({ error: "invalid_api_key" }, 401);
    }
    if (rateLimitSecret.length < 32) {
      throw new Error("RATE_LIMIT_SECRET must contain at least 32 characters");
    }

    let input: unknown;
    try {
      input = JSON.parse(await readLimitedBody(request));
    } catch (error) {
      if (error instanceof RangeError) return respond({ error: "request_too_large" }, 413);
      return respond({ error: "invalid_json" }, 400);
    }
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      return respond({ error: "invalid_input" }, 400);
    }

    const values = input as Record<string, unknown>;
    if (typeof values.website === "string" && values.website.trim()) {
      return respond({ error: "invalid_input" }, 400);
    }
    const authorName = typeof values.author_name === "string" ? values.author_name.trim() : "";
    const title = typeof values.title === "string" ? values.title.trim() : "";
    const description = typeof values.description === "string" ? values.description.trim() : "";
    const slug = typeof values.slug === "string" ? values.slug : "";
    const skillMd = typeof values.skill_md === "string" ? values.skill_md : "";
    if (
      !authorName || Array.from(authorName).length > 50 ||
      !title || Array.from(title).length > 120 ||
      !description || Array.from(description).length > 500 ||
      !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug) || slug.length > 80 ||
      !skillMd.trim() || byteLength(skillMd) > 30_000
    ) {
      return respond({ error: byteLength(skillMd) > 30_000 ? "skill_too_large" : "invalid_input" }, 400);
    }

    const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0].trim();
    const address = forwarded || request.headers.get("x-real-ip")?.trim();
    if (!address) return respond({ error: "request_source_unavailable" }, 503);
    const ipHash = await hashAddress(address, rateLimitSecret);

    const rateResponse = await fetch(`${supabaseUrl}/rest/v1/rpc/consume_skill_publish_limit`, {
      method: "POST",
      headers: {
        apikey: serverKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ p_ip_hash: ipHash }),
      signal: AbortSignal.timeout(8_000),
    });
    if (!rateResponse.ok) {
      console.error("Rate limit RPC failed", rateResponse.status);
      return respond({ error: "rate_limit_unavailable" }, 503);
    }
    if (await rateResponse.json() !== true) {
      return respond({ error: "rate_limited" }, 429);
    }

    const insertResponse = await fetch(`${supabaseUrl}/rest/v1/skills`, {
      method: "POST",
      headers: {
        apikey: serverKey,
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify({
        author_name: authorName,
        title,
        description,
        slug,
        skill_md: skillMd,
      }),
      signal: AbortSignal.timeout(8_000),
    });
    if (insertResponse.status === 409 || insertResponse.status === 23505) {
      return respond({ error: "duplicate_skill" }, 409);
    }
    if (!insertResponse.ok) {
      const dbError = await insertResponse.json().catch(() => ({}));
      if (dbError.code === "23505") return respond({ error: "duplicate_skill" }, 409);
      console.error("Skill insert failed", insertResponse.status, dbError.code || "unknown");
      return respond({ error: "publish_failed" }, 502);
    }
    return respond({ ok: "true" }, 201);
  } catch (error) {
    console.error("Skill publish failed", error);
    return respond({ error: "publish_unavailable" }, 503);
  }
});
