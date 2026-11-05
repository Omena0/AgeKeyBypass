package dev.omena0.agekeydump

import android.content.ContentValues
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.app.Activity
import androidx.credentials.providerevents.ProviderEventsManager
import androidx.credentials.providerevents.exception.ImportCredentialsException
import androidx.credentials.providerevents.transfer.CredentialTypes
import androidx.credentials.providerevents.transfer.ImportCredentialsRequest
import androidx.credentials.providerevents.transfer.KnownExtensions
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private lateinit var status: TextView
    private lateinit var button: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = TextView(this).apply {
            textSize = 15f
            text = "Ready.\n\nThis app requests passkey credentials from another credential provider and writes the returned CXF JSON to Downloads/AgeKeyDump/."
            setPadding(32, 32, 32, 24)
        }

        button = Button(this).apply {
            text = "Import passkeys"
            setOnClickListener { importPasskeys() }
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(status, LinearLayout.LayoutParams(-1, 0, 1f))
            addView(button, LinearLayout.LayoutParams(-1, -2))
        }

        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun importPasskeys() {
        button.isEnabled = false
        status.text = "Starting credential transfer…"

        scope.launch {
            try {
                val manager = ProviderEventsManager.create(this@MainActivity)
                val request = ImportCredentialsRequest(
                    credentialTypes = setOf(
                        CredentialTypes.CREDENTIAL_TYPE_BASIC_AUTH,
                        CredentialTypes.CREDENTIAL_TYPE_PUBLIC_KEY,
                        CredentialTypes.CREDENTIAL_TYPE_ADDRESS,
                        CredentialTypes.CREDENTIAL_TYPE_NOTE,
                    ),
                    knownExtensions = setOf(
                        KnownExtensions.KNOWN_EXTENSION_SHARED,
                    ),
                )

                val response = manager.importCredentials(this@MainActivity, request)
                val cxf = response.response.responseJson
                val exporter = response.callingAppInfo.packageName

                val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                val jsonFile = saveToDownloads(
                    "agekey-cxf-$stamp.json",
                    "application/json",
                    JSONObject(cxf).toString(2).toByteArray(Charsets.UTF_8)
                )

                val passkeys = findPasskeys(JSONObject(cxf))
                val report = buildString {
                    appendLine("exporterPackage=$exporter")
                    appendLine("passkeys=${passkeys.size}")
                    appendLine()
                    passkeys.forEachIndexed { index, passkey ->
                        val key = passkey.keyB64u
                        appendLine("=== passkey ${index + 1} ===")
                        appendLine("rpId=${passkey.rpId}")
                        appendLine("userName=${passkey.userName}")
                        appendLine("credentialId=${passkey.credentialIdB64u}")
                        appendLine("key(base64url PKCS#8)=$key")
                        appendLine()
                    }
                }
                val reportFile = saveToDownloads(
                    "agekey-passkeys-$stamp.txt",
                    "text/plain",
                    report.toByteArray(Charsets.UTF_8)
                )

                passkeys.forEachIndexed { index, passkey ->
                    val der = decodeBase64Url(passkey.keyB64u)
                    saveToDownloads(
                        "agekey-passkey-${index + 1}-$stamp.pk8",
                        "application/octet-stream",
                        der
                    )
                }

                status.text = buildString {
                    appendLine("Done.")
                    appendLine("Exporter: $exporter")
                    appendLine("Passkeys received: ${passkeys.size}")
                    appendLine()
                    appendLine("Saved to Downloads/AgeKeyDump/:")
                    appendLine(jsonFile)
                    appendLine(reportFile)
                    if (passkeys.isNotEmpty()) {
                        appendLine("agekey-passkey-*.pk8")
                    }
                    appendLine()
                    appendLine("WARNING: these files contain private credential material. Treat them like passwords/secret keys.")
                }
            } catch (e: ImportCredentialsException) {
                status.text = "Credential transfer failed:\n\n${e.javaClass.simpleName}: ${e.message ?: "no message"}"
            } catch (e: Exception) {
                status.text = "Failed:\n\n${e.javaClass.simpleName}: ${e.message ?: "no message"}"
            } finally {
                button.isEnabled = true
            }
        }
    }

    private fun saveToDownloads(fileName: String, mimeType: String, bytes: ByteArray): String {
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, fileName)
            put(MediaStore.Downloads.MIME_TYPE, mimeType)
            put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/AgeKeyDump")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }

        val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: error("MediaStore insert returned null")

        try {
            contentResolver.openOutputStream(uri, "w").use { out ->
                requireNotNull(out) { "Could not open output stream" }
                out.write(bytes)
            }
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            contentResolver.update(uri, values, null, null)
            return fileName
        } catch (t: Throwable) {
            contentResolver.delete(uri, null, null)
            throw t
        }
    }

    private data class Passkey(
        val rpId: String,
        val userName: String,
        val credentialIdB64u: String,
        val keyB64u: String
    )

    private fun findPasskeys(root: JSONObject): List<Passkey> {
        val result = mutableListOf<Passkey>()
        walkJson(root, result)
        return result
    }

    private fun walkJson(value: Any?, out: MutableList<Passkey>) {
        when (value) {
            is JSONObject -> {
                if (value.optString("type") == "passkey" && value.has("key")) {
                    out += Passkey(
                        rpId = value.optString("rpId"),
                        userName = value.optString("userName", value.optString("username")),
                        credentialIdB64u = value.optString("credentialId"),
                        keyB64u = value.getString("key")
                    )
                }

                val keys = value.keys()
                while (keys.hasNext()) {
                    walkJson(value.get(keys.next()), out)
                }
            }
            is JSONArray -> {
                for (i in 0 until value.length()) {
                    walkJson(value.get(i), out)
                }
            }
        }
    }

    private fun decodeBase64Url(value: String): ByteArray {
        return Base64.getUrlDecoder().decode(value)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
