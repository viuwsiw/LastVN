// ORIGIN — например, http://vpn.example.com. XHTTP_PATH — путь из lastvn.env.
export default {
  async fetch(request, env) {
    const incoming = new URL(request.url);
    const path = env.XHTTP_PATH?.replace(/\/+$/, "");
    if (!env.ORIGIN || !path?.startsWith("/")) {
      return new Response("Worker configuration missing", { status: 503 });
    }
    if (incoming.pathname !== path && !incoming.pathname.startsWith(path + "/")) {
      return new Response("Not found", { status: 404 });
    }
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405, headers: { Allow: "POST" } });
    }

    const upstream = new URL(env.ORIGIN);
    upstream.pathname = incoming.pathname;
    upstream.search = incoming.search;
    const headers = new Headers(request.headers);
    headers.delete("host");
    headers.delete("connection");

    return fetch(upstream, {
      method: "POST",
      headers,
      body: request.body,
      redirect: "manual",
    });
  },
};
