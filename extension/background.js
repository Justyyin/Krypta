// Connects web pages and the toolbar popup to the local Krypta app.
// The website's origin is always taken from the browser, never from the page itself.

const HOST = "com.krypta.passkeys";

const isSupported = (origin) => /^https:\/\//.test(origin) || /^http:\/\/localhost(:\d+)?$/.test(origin);

// Passkey requests from pages (page.js -> content.js -> here).
function handlePasskey(message, sender, sendResponse) {
  // Only top-level pages: requests from embedded frames go to the browser's own passkey dialog.
  if (!sender.tab || sender.frameId !== 0) {
    sendResponse({ ok: false, fallback: true, error: "frame" });
    return false;
  }
  let origin;
  try {
    origin = sender.origin || new URL(sender.url).origin;
  } catch {
    sendResponse({ ok: false, fallback: true, error: "origin" });
    return false;
  }
  chrome.runtime
    .sendNativeMessage(HOST, { type: message.type, origin, options: message.options })
    .then(
      (response) => sendResponse(response || { ok: false, fallback: true }),
      (error) => sendResponse({ ok: false, fallback: true, error: String(error && error.message) })
    );
  return true; // keep the channel open for the asynchronous answer
}

// Runs inside the page: puts user name and password into the login form.
function fillLogin(username, password) {
  const visible = (el) => el.offsetParent !== null && !el.disabled && !el.readOnly;
  const isUserField = (el) => ["text", "email", "tel", ""].includes(el.type);
  const setValue = (el, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const inputs = [...document.querySelectorAll("input")].filter(visible);
  const passwordField = inputs.find((el) => el.type === "password");
  let userField;
  if (passwordField) {
    const before = inputs.slice(0, inputs.indexOf(passwordField)).filter(isUserField);
    userField = before[before.length - 1];
  } else {
    userField = inputs.find((el) => isUserField(el) && /user|email|login|name/i.test(el.autocomplete + el.name + el.id));
  }
  if (userField && username) setValue(userField, username);
  if (passwordField && password) setValue(passwordField, password);
  return { user: Boolean(userField), password: Boolean(passwordField) };
}

// Requests from the toolbar popup: list the logins for the open page, or fill one in.
async function handlePopup(message) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let origin = "";
  try {
    origin = new URL(tab.url).origin;
  } catch {
    // no readable address
  }
  if (!tab || !isSupported(origin)) return { ok: false, error: "no-page" };

  const response = await chrome.runtime.sendNativeMessage(HOST, { type: message.type, origin, id: message.id });
  if (message.type !== "fill" || !response || !response.ok) return response || { ok: false, error: "not-running" };

  // The page may have changed while Krypta asked for confirmation: fill only the same site.
  const current = await chrome.tabs.get(tab.id);
  if (new URL(current.url).origin !== origin) return { ok: false, error: "page-changed" };

  const [result] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: fillLogin,
    args: [response.username || "", response.password || ""],
  });
  // The password goes to the page only; the popup just learns whether it worked.
  return { ok: true, filled: result && result.result };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message) return false;
  if (message.target === "krypta" && (message.type === "create" || message.type === "get")) {
    return handlePasskey(message, sender, sendResponse);
  }
  // Only the extension's own popup may ask for logins, never a web page.
  if (message.target === "krypta-popup" && !sender.tab && (message.type === "logins" || message.type === "fill")) {
    handlePopup(message).then(sendResponse, () => sendResponse({ ok: false, error: "not-running" }));
    return true;
  }
  return false;
});
