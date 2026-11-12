// Toolbar popup: shows the logins saved for the open website and fills one in on click.
// Krypta asks for confirmation in its own window before it hands out a password.

const list = document.getElementById("logins");
const status = document.getElementById("status");
const text = (key) => chrome.i18n.getMessage(key) || key;

const explain = (error) =>
  ({
    "locked": text("popupLocked"),
    "not-running": text("popupNotRunning"),
    "no-page": text("popupNoPage"),
    "declined": text("popupDeclined"),
    "page-changed": text("popupPageChanged"),
  })[error] || text("popupNotRunning");

async function ask(type, id) {
  try {
    return (await chrome.runtime.sendMessage({ target: "krypta-popup", type, id })) || { ok: false, error: "not-running" };
  } catch {
    return { ok: false, error: "not-running" };
  }
}

async function fill(id) {
  status.textContent = text("popupConfirm");
  const response = await ask("fill", id);
  if (!response.ok) {
    status.textContent = explain(response.error);
    return;
  }
  if (response.filled && response.filled.password) window.close();
  else status.textContent = text("popupNoForm");
}

async function load() {
  const response = await ask("logins");
  if (!response.ok) {
    status.textContent = explain(response.error);
    return;
  }
  const logins = response.logins || [];
  if (logins.length === 0) {
    status.textContent = text("popupNone");
    return;
  }
  status.textContent = "";
  for (const login of logins) {
    const button = document.createElement("button");
    button.className = "login";
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = login.title;
    const user = document.createElement("div");
    user.className = "user";
    user.textContent = login.username;
    button.append(title, user);
    button.addEventListener("click", () => fill(login.id));
    const item = document.createElement("li");
    item.append(button);
    list.append(item);
  }
}

load();
