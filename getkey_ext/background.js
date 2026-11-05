const DB_NAME = "agekey-authenticator";
const DB_VERSION = 1;
const STORE_NAME = "credentials";
const LOG_PREFIX = "[AgeKeyExt]";
const DEFAULT_CONFIG = { origin: "https://agekey.org", rpId: "auth.agekey.org", armed: true };
let attachInitialization;

function autoAttach(reason, force = false) {
  const attempt = async () => {
    try {
      if ((await getAllCredentials()).length && !force) {
        log("proxy attach skipped because a credential already exists; bypass_ext owns assertion mode");
        return;
      }
      const { armedConfig } = await chrome.storage.local.get("armedConfig");
      const config = { ...DEFAULT_CONFIG, ...(armedConfig || {}), armed: true };
      await chrome.storage.local.set({ armedConfig: config });
      await chrome.webAuthenticationProxy.attach();
      log("proxy auto-attached", { reason, origin: config.origin, rpId: config.rpId });
    } catch (error) { logError("automatic proxy attach failed", { reason, ...errorDetails(error) }); }
  };
  if (!attachInitialization) attachInitialization = Promise.resolve().then(attempt);
  else if (force) attachInitialization = attachInitialization.then(attempt);
  return attachInitialization;
}
chrome.runtime.onStartup.addListener(() => void autoAttach("browser startup"));
chrome.runtime.onInstalled.addListener(() => void autoAttach("extension install/update", true));
void autoAttach("service worker startup");

function log(event, details = {}) {
  console.log(LOG_PREFIX, new Date().toISOString(), event, details);
}

function errorDetails(error) {
  return { name: error?.name || "Error", message: error?.message || String(error), stack: error?.stack || "" };
}

function logError(event, details) {
  console.error(`${LOG_PREFIX} ${event}\n${JSON.stringify(details, null, 2)}`);
}

function credentialIds(entries = []) {
  return entries.map((entry) => entry.id);
}

async function recordActivity(kind, outcome, message = "", details = {}) {
  await chrome.storage.local.set({ lastActivity: {
    kind,
    outcome,
    message: String(message).slice(0, 500),
    rpId: details.rpId || "",
    origin: details.origin || "",
    credentialId: details.credentialId || "",
    at: Date.now()
  } });
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "credentialId" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Could not open credential storage."));
  });
}

async function storeOperation(mode, operation) {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, mode);
    const store = tx.objectStore(STORE_NAME);
    let result;
    try {
      result = operation(store);
    } catch (error) {
      reject(error);
      return;
    }
    tx.oncomplete = () => resolve(result?.result);
    tx.onerror = () => reject(tx.error || new Error("Credential storage failed."));
    tx.onabort = () => reject(tx.error || new Error("Credential storage was interrupted."));
  });
}

async function getAllCredentials() {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const request = tx.objectStore(STORE_NAME).getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error || new Error("Could not read credentials."));
  });
}

async function getCredential(credentialId) {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const request = tx.objectStore(STORE_NAME).get(credentialId);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error || new Error("Could not read credential."));
  });
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  if (typeof value !== "string") throw new TypeError("Expected a base64url string.");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function concatBytes(...parts) {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function cborHead(major, value) {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value < 0x100) return Uint8Array.of((major << 5) | 24, value);
  if (value < 0x10000) return Uint8Array.of((major << 5) | 25, value >> 8, value & 255);
  if (value < 0x100000000) {
    return Uint8Array.of((major << 5) | 26, value >>> 24, value >>> 16, value >>> 8, value);
  }
  throw new RangeError("CBOR value is too large.");
}

function cborEncode(value) {
  if (value instanceof Uint8Array) return concatBytes(cborHead(2, value.length), value);
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concatBytes(cborHead(3, bytes.length), bytes);
  }
  if (typeof value === "number" && Number.isInteger(value)) {
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (Array.isArray(value)) {
    return concatBytes(cborHead(4, value.length), ...value.map(cborEncode));
  }
  if (value instanceof Map) {
    const entries = [...value.entries()];
    return concatBytes(
      cborHead(5, entries.length),
      ...entries.flatMap(([key, item]) => [cborEncode(key), cborEncode(item)])
    );
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value);
    return concatBytes(
      cborHead(5, entries.length),
      ...entries.flatMap(([key, item]) => [cborEncode(key), cborEncode(item)])
    );
  }
  throw new TypeError("Unsupported CBOR value.");
}

function getArmedConfig() {
  return chrome.storage.local.get(["armedConfig"]).then(({ armedConfig }) => {
    if (!armedConfig?.armed || !armedConfig.origin || !armedConfig.rpId) {
      throw new DOMException("Authenticator is not armed for a relying party.", "NotAllowedError");
    }
    return armedConfig;
  });
}

function requireTarget(config, rpId) {
  if (!rpId || rpId.toLowerCase() !== config.rpId.toLowerCase()) {
    throw new DOMException(`The request RP ID is ${rpId || "missing"}, but the authenticator is armed for ${config.rpId}. Set the RP ID to ${rpId || "the request's RP ID"} and arm again.`, "NotAllowedError");
  }
}

function findCredentialRequest(requestInfo) {
  return JSON.parse(requestInfo.requestDetailsJson);
}

function rpHash(rpId) {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)).then((hash) => new Uint8Array(hash));
}

function makeClientData(type, challenge, origin) {
  return new TextEncoder().encode(JSON.stringify({
    type,
    challenge,
    origin,
    crossOrigin: false
  }));
}

function userVerificationMode(options) {
  return options.userVerification || "preferred";
}

async function authorize(requestId, options, config, credentialDetails) {
  log("automatic request approval", { requestId, kind: credentialDetails.kind, rpId: config.rpId,
    userVerification: userVerificationMode(options) });
  return { uv: false };
}

async function saveNewCredential(options, config, requestId) {
  const publicKey = options.publicKey || options;
  log("create options", {
    requestId,
    origin: config.origin,
    rpId: publicKey.rp?.id || config.rpId,
    challengeLength: publicKey.challenge?.length || 0,
    userName: publicKey.user?.name || "",
    userDisplayName: publicKey.user?.displayName || "",
    algorithms: publicKey.pubKeyCredParams?.map(({ type, alg }) => ({ type, alg })) || [],
    authenticatorSelection: publicKey.authenticatorSelection || {},
    userVerification: userVerificationMode(publicKey),
    excludeCredentialIds: credentialIds(publicKey.excludeCredentials)
  });
  requireTarget(config, publicKey.rp?.id || config.rpId);
  if (typeof publicKey.challenge !== "string" || !publicKey.challenge) {
    throw new DOMException("The WebAuthn challenge is missing.", "NotAllowedError");
  }
  if (!Array.isArray(publicKey.pubKeyCredParams) || !publicKey.pubKeyCredParams.some((entry) => entry.type === "public-key" && entry.alg === -7)) {
    throw new DOMException("This authenticator supports ES256 (alg -7) only.", "NotSupportedError");
  }
  const rpId = publicKey.rp?.id || config.rpId;
  const excludeIds = new Set((publicKey.excludeCredentials || []).map((entry) => entry.id));
  const existing = (await getAllCredentials()).find((credential) => credential.rpId === rpId && excludeIds.has(credential.credentialId));
  if (existing) throw new DOMException("A matching credential is already registered.", "InvalidStateError");

  const decision = await authorize(requestId, publicKey, config, {
    kind: "create", username: publicKey.user?.name || publicKey.user?.displayName || ""
  });

  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const publicKeySpki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const privateKey = pair.privateKey;

  const credentialId = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const userHandle = bytesToBase64Url(base64UrlToBytes(publicKey.user.id));
  const createdAt = Date.now();
  await storeOperation("readwrite", (store) => store.add({
    credentialId,
    rpId,
    origin: config.origin,
    username: publicKey.user.name || "",
    displayName: publicKey.user.displayName || "",
    userHandle,
    privateKey,
    publicKey: { x: publicJwk.x, y: publicJwk.y },
    createdAt
  }));
  log("credential stored locally", { requestId, rpId, credentialId, userName: publicKey.user?.name || "", createdAt });

  const clientDataJSON = makeClientData("webauthn.create", publicKey.challenge, config.origin);
  const coseKey = new Map([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, base64UrlToBytes(publicJwk.x)],
    [-3, base64UrlToBytes(publicJwk.y)]
  ]);
  const credentialBytes = base64UrlToBytes(credentialId);
  const rpIdHash = await rpHash(rpId);
  // Compatibility mode for AgeKey's UV requirement. No local PIN, biometric,
  // or other verification ceremony is performed by this software authenticator.
  const flags = 0x01 | 0x04 | 0x40;
  const authData = concatBytes(
    rpIdHash,
    Uint8Array.of(flags),
    Uint8Array.of(0, 0, 0, 0),
    new Uint8Array(16),
    Uint8Array.of(credentialBytes.length >> 8, credentialBytes.length & 255),
    credentialBytes,
    cborEncode(coseKey)
  );
  const attestationObject = cborEncode({ fmt: "none", attStmt: {}, authData });
  log("create response built", {
    requestId, credentialId, rpId, origin: config.origin,
    authenticatorFlags: flags, userVerificationReported: true, userVerificationPerformed: false,
    signatureCounter: 0, attestationFormat: "none",
    attestationObjectBytes: attestationObject.length,
    publicKeyAlgorithm: -7, publicKeySpkiBytes: publicKeySpki.length
  });
  const extensionResults = publicKey.extensions?.credProps ? { credProps: { rk: true } } : {};

  return JSON.stringify({
    id: credentialId,
    rawId: credentialId,
    response: {
      clientDataJSON: bytesToBase64Url(clientDataJSON),
      attestationObject: bytesToBase64Url(attestationObject),
      authenticatorData: bytesToBase64Url(authData),
      publicKey: bytesToBase64Url(publicKeySpki),
      publicKeyAlgorithm: -7,
      transports: ["internal"]
    },
    authenticatorAttachment: "platform",
    clientExtensionResults: extensionResults,
    type: "public-key"
  });
}

async function handleCreate(requestInfo) {
  let config;
  let rpId = "";
  try {
    log("create request received", { requestId: requestInfo.requestId,
      requestDetailsJsonLength: requestInfo.requestDetailsJson?.length || 0 });
    config = await getArmedConfig();
    const options = findCredentialRequest(requestInfo);
    rpId = options.publicKey?.rp?.id || options.rp?.id || config.rpId;
    await recordActivity("create", "processing", "Waiting for approval.", { rpId, origin: config.origin });
    const responseJson = await saveNewCredential(options, config, String(requestInfo.requestId));
    const credentialId = JSON.parse(responseJson).id;
    try {
      await chrome.webAuthenticationProxy.completeCreateRequest({ requestId: requestInfo.requestId, responseJson });
    } catch (error) {
      await storeOperation("readwrite", (store) => store.delete(credentialId));
      log("removed credential after Chrome rejected create response", { requestId: requestInfo.requestId, credentialId });
      throw error;
    }
    log("create response submitted to Chrome", { requestId: requestInfo.requestId,
      credentialId });
    await recordActivity("create", "success", "Credential response delivered to the page; server registration is not confirmed.", {
      rpId, origin: config.origin, credentialId: JSON.parse(responseJson).id
    });
    try {
      const bundle = await makeCredentialBundle(credentialId);
      await downloadCredentialBundle(bundle);
      await chrome.webAuthenticationProxy.detach();
      log("proxy detached after registration", { credentialId });
    } catch (exportError) {
      logError("registration response delivered, but automatic bundle export failed", { credentialId, ...errorDetails(exportError) });
    }
  } catch (error) {
    logError("create request failed", { requestId: requestInfo.requestId, ...errorDetails(error) });
    await recordActivity("create", "error", error.message || error.name || "WebAuthn request failed.", { rpId, origin: config?.origin });
    try {
      await chrome.webAuthenticationProxy.completeCreateRequest({
        requestId: requestInfo.requestId,
        error: { name: error.name || "NotAllowedError", message: error.message || "WebAuthn request failed." }
      });
    } catch { /* The page may already have canceled or timed out the request. */ }
  }
}

chrome.webAuthenticationProxy.onCreateRequest.addListener((requestInfo) => {
  log("onCreateRequest event", { requestId: requestInfo.requestId });
  void handleCreate(requestInfo);
});

chrome.webAuthenticationProxy.onGetRequest.addListener((requestInfo) => {
  log("get request rejected by key-export-only extension", { requestId: requestInfo.requestId });
  void chrome.webAuthenticationProxy.completeGetRequest({
    requestId: requestInfo.requestId,
    error: { name: "NotAllowedError", message: "This extension only creates and exports credentials." }
  }).catch((error) => logError("get rejection failed", { requestId: requestInfo.requestId, ...errorDetails(error) }));
});

chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((requestInfo) => {
  log("onIsUvpaaRequest event", { requestId: requestInfo.requestId });
  void chrome.storage.local.get("armedConfig").then(({ armedConfig }) => {
    const isUvpaa = Boolean(armedConfig?.armed);
    log("isUVPAA response", { requestId: requestInfo.requestId, isUvpaa });
    return chrome.webAuthenticationProxy.completeIsUvpaaRequest({
      requestId: requestInfo.requestId,
      isUvpaa
    });
  }).catch((error) => logError("isUVPAA handling failed", {
    requestId: requestInfo.requestId, ...errorDetails(error)
  }));
});

chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => {
  log("onRequestCanceled event", { requestId });
  void recordActivity("request", "canceled", "The page canceled or timed out its WebAuthn request.");
});

async function makeCredentialBundle(credentialId) {
  const credential = await getCredential(credentialId);
  if (!credential) throw new Error("Newly registered credential was not found for export.");
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", credential.privateKey);
  const safeRpId = credential.rpId.replace(/[^a-z0-9.-]/gi, "_");
  const safeUsername = (credential.username || "passkey").replace(/[^a-z0-9._-]/gi, "_").slice(0, 80);
  return {
    filename: `agekey-${safeRpId}-${safeUsername}.json`,
    bundle: {
      format: "agekey-bypass-credential", version: 1,
      credentialId: credential.credentialId, rpId: credential.rpId,
      userHandle: credential.userHandle, username: credential.username || "",
      displayName: credential.displayName || "", algorithm: "ES256",
      privateKeyFormat: "PKCS#8", privateKey: bytesToBase64Url(pkcs8)
    }
  };
}

async function downloadCredentialBundle({ filename, bundle }) {
  try {
    const url = `data:application/json;base64,${btoa(unescape(encodeURIComponent(JSON.stringify(bundle, null, 2))))}`;
    await chrome.downloads.download({ url, filename, saveAs: false });
    log("JSON credential bundle download started", { credentialId: bundle.credentialId, rpId: bundle.rpId });
  } catch (error) { logError("automatic JSON export failed", { credentialId: bundle?.credentialId, ...errorDetails(error) }); }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    if (message?.type === "getState") {
      const [{ armedConfig, lastActivity }, credentials] = await Promise.all([
        chrome.storage.local.get(["armedConfig", "lastActivity"]),
        getAllCredentials()
      ]);
      return {
        ok: true,
        apiAvailable: Boolean(chrome.webAuthenticationProxy),
        config: armedConfig || null,
        lastActivity: lastActivity || null,
        credentials: credentials.map(({ credentialId, rpId, username, displayName, userHandle, createdAt }) => ({
          credentialId, rpId, username, displayName, userHandle, createdAt
        }))
      };
    }

    if (message?.type === "arm") {
      const originUrl = new URL(message.origin);
      if (!/^https?:$/.test(originUrl.protocol)) throw new Error("Choose an HTTP(S) relying-party page.");
      const rpId = String(message.rpId || "").trim().toLowerCase();
      if (!rpId || /[^a-z0-9.-]/.test(rpId) || rpId.startsWith(".") || rpId.endsWith(".") || rpId.includes("..")) {
        throw new Error("Enter the RP ID as a hostname only, without a scheme or path.");
      }
      const config = { origin: originUrl.origin, rpId, armed: true };
      log("arming proxy", config);
      await chrome.storage.local.set({ armedConfig: config });
      try {
        await chrome.webAuthenticationProxy.attach();
        log("proxy attached", config);
      } catch (error) {
        logError("proxy attach failed", { ...config, ...errorDetails(error) });
        await chrome.storage.local.set({ armedConfig: { ...config, armed: false } });
        throw error;
      }
      return { ok: true, config };
    }

    if (message?.type === "disarm") {
      log("disarming proxy");
      await chrome.webAuthenticationProxy.detach();
      const { armedConfig } = await chrome.storage.local.get(["armedConfig"]);
      if (armedConfig) await chrome.storage.local.set({ armedConfig: { ...armedConfig, armed: false } });
      log("proxy detached", { previousConfig: armedConfig || null });
      return { ok: true };
    }

    if (message?.type === "exportCredentialKey") {
      const credential = await getCredential(message.credentialId);
      if (!credential) throw new Error("Credential no longer exists.");
      const pkcs8 = await crypto.subtle.exportKey("pkcs8", credential.privateKey);
      log("private key exported", { credentialId: credential.credentialId, rpId: credential.rpId,
        pkcs8Bytes: pkcs8.byteLength });
      const safeRpId = credential.rpId.replace(/[^a-z0-9.-]/gi, "_");
      const safeUsername = (credential.username || "passkey").replace(/[^a-z0-9._-]/gi, "_").slice(0, 80);
      const bundle = {
        format: "agekey-bypass-credential",
        version: 1,
        credentialId: credential.credentialId,
        rpId: credential.rpId,
        userHandle: credential.userHandle,
        username: credential.username || "",
        displayName: credential.displayName || "",
        algorithm: "ES256",
        privateKeyFormat: "PKCS#8",
        privateKey: bytesToBase64Url(pkcs8)
      };
      return {
        ok: true,
        filename: `agekey-${safeRpId}-${safeUsername}.json`,
        bundle
      };
    }

    if (message?.type === "removeCredential") {
      log("deleting local credential", { credentialId: message.credentialId });
      await storeOperation("readwrite", (store) => store.delete(message.credentialId));
      return { ok: true };
    }

    throw new Error("Unknown extension message.");
  })().then(sendResponse).catch((error) => {
    logError("extension message failed", {
      type: message?.type, ...errorDetails(error)
    });
    sendResponse({ ok: false, error: error instanceof Error ? error.message : String(error) });
  });
  return true;
});
