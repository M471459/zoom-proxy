// api/zoom-webhook.js  -- solo validación de Zoom
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
  } catch (e) {
    return new Response(
      JSON.stringify({ ok: false, err: "JSON parse error" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const event = json?.event || "";
  const secret = process.env.ZOOM_WEBHOOK_SECRET;

  if (event === "endpoint.url_validation") {
    if (!secret) {
      return new Response(
        JSON.stringify({ ok: false, err: "Missing ZOOM_WEBHOOK_SECRET" }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
    const plain = json?.payload?.plainToken || "";
    const enc = await hmacSHA256Hex(plain, secret);
    return new Response(
      JSON.stringify({ plainToken: plain, encryptedToken: enc }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  return new Response(
    JSON.stringify({ ok: true, note: "not a validation event" }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }
  );
}
