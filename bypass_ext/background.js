const DB_NAME = "agekey-assertion-keys";
const DB_VERSION = 1;
const STORE_NAME = "keys";
const pending = new Map();
const PREFIX = "[AgeKeyBypass]";
const DEFAULT_CONFIG = { origin: "https://agekey.org", rpId: "auth.agekey.org", armed: true };
let attachInitialization;

function log(event, data = {}) { console.log(PREFIX, new Date().toISOString(), event, data); }
function logError(event, error, extra = {}) {
  console.error(`${PREFIX} ${event}\n${JSON.stringify({ ...extra, name: error?.name, message: error?.message || String(error), stack: error?.stack }, null, 2)}`);
}

async function attachProxy(reason) {
  const { config } = await chrome.storage.local.get("config");
  const activeConfig = { ...DEFAULT_CONFIG, ...(config || {}), armed: true };
  await chrome.storage.local.set({ config: activeConfig });
  await chrome.webAuthenticationProxy.attach();
  log("proxy attached", { reason, origin: activeConfig.origin, rpId: activeConfig.rpId });
}

function autoAttach(reason) {
  if (!attachInitialization) attachInitialization = (async () => {
    try {
      await attachProxy(reason);
    } catch (error) {
      logError("automatic proxy attach failed; another extension may own the WebAuthn proxy", error, { reason });
    }
  })();
  return attachInitialization;
}

// Attach without requiring the user to open the action popup. Running this at
// worker startup also reattaches after a browser restart or extension reload.
chrome.runtime.onStartup.addListener(() => void autoAttach("browser startup"));
chrome.runtime.onInstalled.addListener(() => void autoAttach("extension install/update"));
void autoAttach("service worker startup");

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME, { keyPath: "credentialId" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Could not open key storage."));
  });
}

async function store(mode, action) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, mode);
    let request;
    try { request = action(tx.objectStore(STORE_NAME)); }
    catch (error) { reject(error); return; }
    tx.oncomplete = () => resolve(request?.result);
    tx.onerror = () => reject(tx.error || new Error("Key storage failed."));
    tx.onabort = () => reject(tx.error || new Error("Key storage was interrupted."));
  });
}

async function getKey(credentialId) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(credentialId);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error || new Error("Could not read the selected key."));
  });
}

async function allKeys() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error || new Error("Could not list keys."));
  });
}

function b64url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function unb64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

function ecdsaDer(raw) {
  const sig = new Uint8Array(raw);
  if (sig.length !== 64) throw new Error(`Expected a 64-byte P-256 signature, got ${sig.length}.`);
  const integer = (part) => {
    let i = 0;
    while (i < part.length - 1 && part[i] === 0) i++;
    let value = part.slice(i);
    if (value[0] & 0x80) value = concat(Uint8Array.of(0), value);
    return concat(Uint8Array.of(2, value.length), value);
  };
  const body = concat(integer(sig.slice(0, 32)), integer(sig.slice(32)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

function makeClientData(challenge, origin) {
  return new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
}

function getConfig() {
  return chrome.storage.local.get("config").then(({ config }) => {
    if (!config?.armed || !config.origin || !config.rpId) throw new DOMException("Arm the assertion extension first.", "NotAllowedError");
    return config;
  });
}

function showPrompt(requestId, details) {
  return new Promise((resolve) => {
    const finish = (decision) => {
      clearTimeout(timer);
      const item = pending.get(requestId);
      pending.delete(requestId);
      if (item?.windowId != null) chrome.windows.remove(item.windowId).catch(() => {});
      resolve(decision);
    };
    const timer = setTimeout(() => finish({ allow: false }), 90_000);
    pending.set(requestId, { details, finish, windowId: null });
    chrome.windows.create({ url: chrome.runtime.getURL(`confirm.html?requestId=${encodeURIComponent(requestId)}`), type: "popup", width: 470, height: 560 })
      .then((window) => { const item = pending.get(requestId); if (item) item.windowId = window.id; })
      .catch(() => finish({ allow: false }));
  });
}

async function assertionOptions(requestInfo, config) {
  const options = JSON.parse(requestInfo.requestDetailsJson);
  const rpId = options.rpId || config.rpId;
  log("assertion options", { requestId: requestInfo.requestId, rpId, origin: config.origin,
    challengeLength: options.challenge?.length || 0, userVerification: options.userVerification || "preferred",
    allowCredentialIds: (options.allowCredentials || []).map(({ id }) => id) });
  if (rpId.toLowerCase() !== config.rpId.toLowerCase()) throw new DOMException(`Request RP ID ${rpId} does not match armed RP ID ${config.rpId}.`, "NotAllowedError");
  if (typeof options.challenge !== "string" || !options.challenge) throw new DOMException("The WebAuthn challenge is missing.", "NotAllowedError");

  const descriptors = Array.isArray(options.allowCredentials) ? options.allowCredentials : [];
  let local = await allKeys();
  local = local.filter((item) => item.rpId === rpId);
  let candidates = local;
  if (descriptors.length) {
    const allowed = new Set(descriptors.map((entry) => entry.id));
    candidates = local.filter((item) => allowed.has(item.credentialId));
  }
  const visibleCandidates = descriptors.length
    ? descriptors.map((descriptor) => {
      const match = candidates.find((item) => item.credentialId === descriptor.id);
      return { credentialId: descriptor.id, stored: Boolean(match), userHandle: match?.userHandle || "" };
    })
    : candidates.map((item) => ({ credentialId: item.credentialId, stored: true, userHandle: item.userHandle || "" }));
  log("assertion key matches", { requestId: requestInfo.requestId,
    localKeyCount: candidates.length, candidateCount: visibleCandidates.length });

  return { options, rpId, candidates, visibleCandidates };
}

async function handleGet(requestInfo) {
  const id = String(requestInfo.requestId);
  let config;
  try {
    log("get request", { requestId: id, detailsLength: requestInfo.requestDetailsJson?.length || 0 });
    config = await getConfig();
    const { options, rpId, candidates, visibleCandidates } = await assertionOptions(requestInfo, config);
    const details = {
      origin: config.origin, rpId, kind: "assertion",
      userVerification: options.userVerification || "preferred",
      discoverable: !(options.allowCredentials || []).length,
      requiresPin: false,
      pinAvailable: false,
      developmentPin: false,
      candidates: candidates.map(({ credentialId, username, userHandle }) => ({ credentialId, username: username || "", userHandle: userHandle || "", stored: true })),
      allowCredentialIds: (options.allowCredentials || []).map(({ id }) => id),
      allowListEmpty: !(options.allowCredentials || []).length
    };
    const decision = await showPrompt(id, details);
    if (!decision.allow) throw new DOMException("The assertion was denied or canceled.", "NotAllowedError");
    const credentialId = decision.credentialId;
    if (!credentialId) throw new Error("Choose a key or use Add key to import a bundle.");
    const credential = await getKey(credentialId);
    if (!credential) throw new Error("The selected key is no longer stored. Add its JSON bundle again.");
    if (credential.rpId !== rpId) throw new Error("Selected key is saved for a different RP ID.");
    if (!(options.allowCredentials || []).length && !credential.userHandle) {
      throw new Error("This discoverable request needs the original WebAuthn user handle. Re-add its JSON bundle.");
    }

    const clientDataJSON = makeClientData(options.challenge, config.origin);
    const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)));
    // Compatibility mode requested for this test authenticator: set UV even
    // though no PIN, biometric, or other verification ceremony took place.
    const flags = 0x01 | 0x04;
    const authenticatorData = concat(rpHash, Uint8Array.of(flags), Uint8Array.of(0, 0, 0, 0));
    const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
    const rawSignature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, credential.privateKey, concat(authenticatorData, clientDataHash));
    const signature = ecdsaDer(rawSignature);
    // userHandle is the WebAuthn user.id (opaque bytes), passed in base64url.
    const userHandle = credential.userHandle || null;
    const responseJson = JSON.stringify({
      id: credentialId,
      rawId: credentialId,
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authenticatorData),
        signature: b64url(signature),
        userHandle: userHandle ? b64url(unb64url(userHandle)) : null
      },
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      type: "public-key"
    });
    await chrome.webAuthenticationProxy.completeGetRequest({ requestId: requestInfo.requestId, responseJson });
    const { lastActivity = [] } = await chrome.storage.local.get("lastActivity");
    await chrome.storage.local.set({ lastActivity: [{ at: Date.now(), outcome: "success", credentialId, rpId, origin: config.origin }, ...lastActivity].slice(0, 20) });
    log("assertion submitted", { requestId: id, credentialId, rpId, origin: config.origin, flags,
      userVerificationReported: true, userVerificationPerformed: false, signatureBytes: signature.length });
  } catch (error) {
    logError("assertion failed", error, { requestId: id, rpId: config?.rpId || "", origin: config?.origin || "" });
    try {
      await chrome.webAuthenticationProxy.completeGetRequest({
        requestId: requestInfo.requestId,
        error: { name: error.name || "NotAllowedError", message: error.message || "Assertion failed." }
      });
    } catch (completeError) { logError("failed to report assertion error", completeError, { requestId: id }); }
    const { lastActivity = [] } = await chrome.storage.local.get("lastActivity");
    await chrome.storage.local.set({ lastActivity: [{ at: Date.now(), outcome: "error", message: error.message || String(error), rpId: config?.rpId || "", origin: config?.origin || "" }, ...lastActivity].slice(0, 20) });
  }
}

chrome.webAuthenticationProxy.onGetRequest.addListener((info) => void handleGet(info));
chrome.webAuthenticationProxy.onCreateRequest.addListener((info) => {
  log("create rejected: assertion-only extension", { requestId: info.requestId });
  void chrome.webAuthenticationProxy.completeCreateRequest({ requestId: info.requestId,
    error: { name: "NotAllowedError", message: "Use getkey_ext to register and export a key. bypass_ext handles assertions only." } });
});
chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((info) => {
  void chrome.storage.local.get("config").then(({ config }) =>
    chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId: info.requestId, isUvpaa: Boolean(config?.armed) })
  ).catch((error) => logError("isUVPAA failed", error, { requestId: info.requestId }));
});
chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => {
  const item = pending.get(String(requestId));
  if (item) item.finish({ allow: false });
  log("request canceled", { requestId });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    if (message?.type === "getState") {
      const [{ config, lastActivity = [] }, keys] = await Promise.all([
        chrome.storage.local.get(["config", "lastActivity"]), allKeys()
      ]);
      return { ok: true, apiAvailable: Boolean(chrome.webAuthenticationProxy), config: config || null,
        keys: keys.map(({ credentialId, rpId, userHandle, username, displayName, createdAt }) => ({ credentialId, rpId, userHandle, username, displayName, createdAt })), lastActivity };
    }
    if (message?.type === "arm") {
      const origin = new URL(message.origin);
      if (!/^https?:$/.test(origin.protocol)) throw new Error("Use an HTTP(S) client-data origin.");
      const rpId = String(message.rpId || "").trim().toLowerCase();
      if (!rpId || /[^a-z0-9.-]/.test(rpId) || rpId.startsWith(".") || rpId.endsWith(".") || rpId.includes("..")) throw new Error("Enter the RP ID as a hostname only.");
      const config = { origin: origin.origin, rpId, armed: true };
      await chrome.storage.local.set({ config });
      try { await chrome.webAuthenticationProxy.attach(); }
      catch (error) { await chrome.storage.local.set({ config: { ...config, armed: false } }); throw error; }
      log("proxy armed", config);
      return { ok: true, config };
    }
    if (message?.type === "disarm") {
      await chrome.webAuthenticationProxy.detach();
      const { config } = await chrome.storage.local.get("config");
      if (config) await chrome.storage.local.set({ config: { ...config, armed: false } });
      log("proxy disarmed", config || {});
      return { ok: true };
    }
    if (message?.type === "getPending") {
      const item = pending.get(String(message.requestId));
      if (!item) throw new Error("Request expired or canceled.");
      return { ok: true, details: item.details };
    }
    if (message?.type === "decide") {
      const item = pending.get(String(message.requestId));
      if (!item) throw new Error("Request expired or canceled.");
      item.finish({ allow: Boolean(message.allow), credentialId: message.credentialId || "",
        pkcs8: message.pkcs8 || "", userHandle: message.userHandle || "" });
      return { ok: true };
    }
    if (message?.type === "importBundle") {
      const bundle = message.bundle;
      if (bundle?.format !== "agekey-bypass-credential" || bundle.version !== 1 || bundle.algorithm !== "ES256" || bundle.privateKeyFormat !== "PKCS#8") {
        throw new Error("Select a JSON key bundle exported by getkey_ext.");
      }
      if (!bundle.credentialId || !bundle.rpId || !bundle.privateKey) throw new Error("The key bundle is missing required fields.");
      const privateKey = await crypto.subtle.importKey("pkcs8", unb64url(bundle.privateKey), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
      await store("readwrite", (objectStore) => objectStore.put({
        credentialId: bundle.credentialId, rpId: bundle.rpId, userHandle: bundle.userHandle || null,
        username: bundle.username || "", displayName: bundle.displayName || "", privateKey, createdAt: Date.now()
      }));
      log("JSON credential bundle imported", { credentialId: bundle.credentialId, rpId: bundle.rpId });
      if (message.requestId) {
        const item = pending.get(String(message.requestId));
        if (!item) throw new Error("The assertion request expired before the key was imported.");
        item.finish({ allow: true, credentialId: bundle.credentialId });
      }
      return { ok: true };
    }
    if (message?.type === "deleteKey") {
      await store("readwrite", (objectStore) => objectStore.delete(message.credentialId));
      return { ok: true };
    }
    throw new Error("Unknown extension message.");
  })().then(sendResponse).catch((error) => {
    logError("message failed", error, { type: message?.type });
    sendResponse({ ok: false, error: error.message || String(error) });
  });
  return true;
});
