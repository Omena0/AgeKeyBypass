const requestId = new URL(location.href).searchParams.get("requestId");
const $ = (id) => document.getElementById(id);
let details;

async function send(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || "Request failed.");
  return response;
}

function showCandidate(candidate) {
  const option = document.createElement("option");
  option.value = candidate.credentialId;
  option.textContent = `${candidate.username || "AgeKey key"} · ${candidate.credentialId}`;
  $("credential").appendChild(option);
}

async function load() {
  try {
    ({ details } = await send({ type: "getPending", requestId }));
    $("summary").textContent = `RP ID ${details.rpId}; choose a key or add its JSON bundle.`;
    for (const candidate of details.candidates || []) showCandidate(candidate);
    $("credential").hidden = !(details.candidates || []).length;
    if (!details.candidates?.length) $("summary").textContent = `No saved key matches ${details.rpId}. Use Add key to select the JSON bundle.`;
  } catch (error) {
    $("summary").textContent = error.message;
    $("allow").disabled = true;
    $("addKey").disabled = true;
  }
}

async function decide(allow) {
  try {
    const response = await send({ type: "decide", requestId, allow, credentialId: $("credential").value });
    window.close();
  } catch (error) { $("error").textContent = error.message; }
}

$("allow").addEventListener("click", () => decide(true));
$("deny").addEventListener("click", () => decide(false));
$("addKey").addEventListener("click", () => $("keyFile").click());
$("keyFile").addEventListener("change", async () => {
  const file = $("keyFile").files[0];
  if (!file) return;
  try {
    const bundle = JSON.parse(await file.text());
    if (bundle?.rpId !== details.rpId) throw new Error(`This bundle is for ${bundle?.rpId || "an unknown RP ID"}, but this request is for ${details.rpId}.`);
    const allowList = details.allowCredentialIds || [];
    const requestAllowsAny = details.allowListEmpty;
    if (!requestAllowsAny && !allowList.includes(bundle.credentialId)) {
      throw new Error("This request did not offer the credential in the selected bundle.");
    }
    await send({ type: "importBundle", bundle, requestId });
    window.close();
  } catch (error) { $("error").textContent = error.message; }
  finally { $("keyFile").value = ""; }
});
load();
