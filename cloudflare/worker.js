// LastVN: Cloudflare Worker для выгрузки (режим split).
// Принимает XHTTP-запросы клиента и пересылает их на сервер (порт 80, nginx -> Xray).
// Пропускает только путь XHTTP — остальное отдаёт заглушкой, чтобы воркер не был открытым прокси.
//
// Перед деплоем поменяй две константы под свой сервер (их печатает `lastvn.sh split`).

const ORIGIN = "213-108-21-54.sslip.io"; // домен сервера (IP.sslip.io)
const PATH = "/06dfadb248cf";            // XHTTP path из конфига

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith(PATH)) {
      return new Response("ok", { headers: { "content-type": "text/plain" } });
    }
    url.protocol = "http:";
    url.hostname = ORIGIN;
    url.port = "80";

    const headers = new Headers(request.headers);
    headers.set("host", ORIGIN);

    const init = { method: request.method, headers, redirect: "manual" };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body; // потоково, без буферизации всего тела
      init.duplex = "half";
    }
    return fetch(url.toString(), init);
  },
};
