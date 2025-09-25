// api/zoom-webhook.js  -- sanity check
export const config = { runtime: "edge" };

export default async function handler(req) {
  return new Response(
    JSON.stringify({ ok: true, path: new URL(req.url).pathname }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }
  );
}
