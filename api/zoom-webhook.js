// api/zoom-webhook.js  -- proxy final
export const config = { runtime: "edge" };

async function hmacSHA256Hex(message, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export default async function handler(req) {
  if (req.method !== "POST") return new Response("Only POST", { status: 405 });

  const bodyText = await req.text();
  let json = {};
  try {
    json = bodyText ? JSON.parse(bodyText) : {};
  } catch {
    return new Response("bad json", { status: 400 });
  }

  const event = json?.event;
  const ZOOM_SECRET = process.env.ZOOM_WEBHOOK_SECRET;
  const ZOHO_URLS = [
    process.env.ZOHO_FUNC_ASISTENCIA,
    process.env.ZOHO_FUNC_REGISTRADOS,
  ];

  // 1) Handshake de Zoom
  if (event === "endpoint.url_validation") {
    if (!ZOOM_SECRET) return new Response("missing secret", { status: 500 });
    const plain = json?.payload?.plainToken || "";
    const enc = await hmacSHA256Hex(plain, ZOOM_SECRET);
    return new Response(
      JSON.stringify({ plainToken: plain, encryptedToken: enc }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // 2) Verificar firma (recomendado)
  if (!ZOOM_SECRET) return new Response("missing secret", { status: 500 });
  const ts = req.headers.get("x-zm-request-timestamp") || "";
  const sig = req.headers.get("x-zm-signature") || "";
  const expected = await hmacSHA256Hex(`v0:${ts}:${bodyText}`, ZOOM_SECRET);
  if (sig !== `v0=${expected}`)
    return new Response("unauthorized", { status: 401 });

  // 3) Reenvío a Zoho (no bloqueante)
  queueMicrotask(async () => {
    const headers = { "Content-Type": "application/json" };
    const tasks = [];
    for (const url of ZOHO_URLS) {
      if (url)
        tasks.push(fetch(url, { method: "POST", headers, body: bodyText }));
    }
    await Promise.allSettled(tasks);
  });

  return new Response("ok", { status: 200 });
}
