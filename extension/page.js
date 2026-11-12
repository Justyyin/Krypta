// Runs inside the web page. Wraps navigator.credentials.create/get so that passkey
// requests are offered to the local Krypta vault first. Whenever Krypta cannot or should
// not answer (app not running, vault stays locked, user chooses "use something else",
// no matching passkey), the browser's own passkey dialog is used as before.

(() => {
  if (!window.PublicKeyCredential || !navigator.credentials) return;

  const nativeCreate = navigator.credentials.create.bind(navigator.credentials);
  const nativeGet = navigator.credentials.get.bind(navigator.credentials);

  const toBase64Url = (buffer) => {
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const fromBase64Url = (text) => {
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  };

  // Turns the options into plain JSON; binary values become base64url strings.
  const toJson = (value) => {
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return toBase64Url(value);
    if (Array.isArray(value)) return value.map(toJson);
    if (value && typeof value === "object") {
      const result = {};
      for (const key of Object.keys(value)) {
        if (typeof value[key] !== "function" && value[key] !== undefined) result[key] = toJson(value[key]);
      }
      return result;
    }
    return value;
  };

  const ask = (type, options) =>
    new Promise((resolve) => {
      const id = crypto.randomUUID();
      const timeout = setTimeout(() => finish({ ok: false, fallback: true }), 5 * 60 * 1000);
      const listener = (event) => {
        if (event.source !== window || !event.data || event.data.krypta !== "response" || event.data.id !== id) return;
        finish(event.data.response);
      };
      const finish = (response) => {
        clearTimeout(timeout);
        window.removeEventListener("message", listener);
        resolve(response || { ok: false, fallback: true });
      };
      window.addEventListener("message", listener);
      window.postMessage({ krypta: "request", id, type, options }, window.location.origin);
    });

  // Builds an object that looks like the browser's own PublicKeyCredential.
  const buildCredential = (json, isCreate) => {
    const r = json.response;
    const response = isCreate
      ? {
          clientDataJSON: fromBase64Url(r.clientDataJSON),
          attestationObject: fromBase64Url(r.attestationObject),
          getTransports: () => r.transports || ["internal"],
          getAuthenticatorData: () => fromBase64Url(r.authenticatorData),
          getPublicKey: () => fromBase64Url(r.publicKey),
          getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
        }
      : {
          clientDataJSON: fromBase64Url(r.clientDataJSON),
          authenticatorData: fromBase64Url(r.authenticatorData),
          signature: fromBase64Url(r.signature),
          userHandle: r.userHandle ? fromBase64Url(r.userHandle) : null,
        };
    const responsePrototype = isCreate ? window.AuthenticatorAttestationResponse : window.AuthenticatorAssertionResponse;
    if (responsePrototype) Object.setPrototypeOf(response, responsePrototype.prototype);

    const credential = {
      id: json.id,
      rawId: fromBase64Url(json.rawId),
      type: "public-key",
      authenticatorAttachment: json.authenticatorAttachment || "platform",
      response,
      getClientExtensionResults: () => json.clientExtensionResults || {},
      toJSON: () => JSON.parse(JSON.stringify(json)),
    };
    Object.setPrototypeOf(credential, window.PublicKeyCredential.prototype);
    return credential;
  };

  const handle = async (type, options, native) => {
    const publicKey = options && options.publicKey;
    // Not a passkey request, or the "autofill" variant that must not open a dialog on page load.
    if (!publicKey || options.mediation === "conditional") return native(options);

    let answer;
    try {
      answer = await ask(type, toJson(publicKey));
    } catch {
      return native(options);
    }
    if (answer.ok && answer.credential) return buildCredential(answer.credential, type === "create");
    if (answer.domError) throw new DOMException(answer.message || "", answer.domError);
    return native(options);
  };

  navigator.credentials.create = (options) => handle("create", options, nativeCreate);
  navigator.credentials.get = (options) => handle("get", options, nativeGet);
})();
