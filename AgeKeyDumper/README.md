
# AgeKeyDump

Minimal Android test app for the Android Credential Transfer API.

It requests only the FIDO CXF `passkey` credential type, imports credentials from the selected credential provider, then saves:

- `agekey-cxf-*.json` — the complete returned CXF payload
- `agekey-passkeys-*.txt` — passkey metadata plus the `key` field
- `agekey-passkey-*.pk8` — the `key` field decoded from base64url into the raw PKCS#8 DER private key

Files are written to `Downloads/AgeKeyDump/` using `MediaStore.Downloads`; no storage permission is declared.

## Build

Open this directory in Android Studio and sync/build. The project uses:

- Android Gradle Plugin 9.4.0
- Kotlin 2.4.10
- `androidx.credentials.providerevents:providerevents:1.0.0-beta01`
- `kotlinx-coroutines-android:1.11.0`
- compileSdk/targetSdk 36
- minSdk 29

## Test

Install the debug APK on the Android device, open the app, and press **Import passkeys**. Select the credential provider containing the passkey(s) and complete its authentication/transfer UI.

The exported private-key files are deliberately written for inspection. Do this only with credentials you are authorized to export.
