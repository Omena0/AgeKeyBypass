const $ = (id) => document.getElementById(id);

async function send(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || "Extension request failed.");
  return response;
}

async function refresh() {
  const state = await send({ type: "getState" });
  const keys = $("keys");
  keys.replaceChildren();
  if (!state.keys.length) {
    $("status").textContent = "No keys yet. Add the JSON bundle exported by getkey_ext.";
    return;
  }
  $("status").textContent = `${state.keys.length} key${state.keys.length === 1 ? "" : "s"}`;
  for (const key of state.keys) {
    const row = document.createElement("div");
    row.className = "key-row";
    const label = document.createElement("span");
    label.textContent = `${key.username || key.displayName || "AgeKey key"} · ${key.rpId} · ${key.credentialId}`;
    const remove = document.createElement("button");
    remove.className = "secondary remove-key";
    remove.textContent = "Remove";
    remove.addEventListener("click", async () => {
      try { await send({ type: "deleteKey", credentialId: key.credentialId }); await refresh(); }
      catch (error) { $("status").textContent = error.message; }
    });
    row.append(label, remove);
    keys.appendChild(row);
  }
}

$("addKey").addEventListener("click", () => $("keyFile").click());
$("keyFile").addEventListener("change", async () => {
  const file = $("keyFile").files[0];
  if (!file) return;
  try {
    const bundle = JSON.parse(await file.text());
    await send({ type: "importBundle", bundle });
    $("status").textContent = "Key added.";
    await refresh();
  } catch (error) { $("status").textContent = error.message; }
  finally { $("keyFile").value = ""; }
});

refresh().catch((error) => { $("status").textContent = error.message; });
