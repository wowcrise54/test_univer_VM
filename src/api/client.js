export function api(path, options = {}) {
  const headers = options.body instanceof FormData ? {} : { "Content-Type": "application/json" };
  return fetch(path, { ...options, headers: { ...headers, ...(options.headers || {}) } }).then(async (response) => {
    const contentType = response.headers.get("content-type") || "";
    const body = contentType.includes("application/json") ? await response.json() : await response.text();
    if (!response.ok) {
      const message = typeof body === "string" ? body : body.detail || JSON.stringify(body);
      throw new Error(message);
    }
    return body;
  });
}
