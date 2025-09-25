zoom - webhook.js; // api/zoom-webhook.js
export const config = { runtime: "edge" };

async function hmacSHA256Hex(message, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
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
  const json = bodyText ? JSON.parse(bodyText) : {};
  const event = json?.event;

  const ZOOM_SECRET = process.env.ZOOM_WEBHOOK_SECRET;
  const ZOHO_URLS = [
    process.env.ZOHO_FUNC_ASISTENCIA, // Invoke URL de registraasistencia
    process.env.ZOHO_FUNC_REGISTRADOS, // Invoke URL de registraconfirmados
  ];

  // 1) Handshake de validación de Zoom
  if (event === "endpoint.url_validation") {
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

  // 2) (Opcional pero recomendado) Verificar firma de Zoom
  const ts = req.headers.get("x-zm-request-timestamp") || "";
  const sig = req.headers.get("x-zm-signature") || "";
  const expected = await hmacSHA256Hex(`v0:${ts}:${bodyText}`, ZOOM_SECRET);
  if (sig !== `v0=${expected}`)
    return new Response("unauthorized", { status: 401 });

  // 3) Responder rápido y reenviar a Zoho en background
  queueMicrotask(async () => {
    await Promise.allSettled(
      ZOHO_URLS.map((url) =>
        fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: bodyText,
        })
      )
    );
  });

  return new Response("ok", { status: 200 });
}
