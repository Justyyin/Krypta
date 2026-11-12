// Runs in the extension's isolated world. Relays messages between the page script
// (page.js) and the extension's background worker.

window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data.krypta !== "request" || typeof data.id !== "string") return;

  const reply = (response) => window.postMessage({ krypta: "response", id: data.id, response }, window.location.origin);

  try {
    chrome.runtime.sendMessage({ target: "krypta", type: data.type, options: data.options }).then(
      (response) => reply(response || { ok: false, fallback: true }),
      () => reply({ ok: false, fallback: true })
    );
  } catch {
    // The extension was reloaded or removed while the page stayed open.
    reply({ ok: false, fallback: true });
  }
});
