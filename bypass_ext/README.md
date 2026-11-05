# bypass_ext

This extension handles WebAuthn assertions only. Its proxy attaches automatically at browser or extension startup. The popup contains the saved key list and **Add key**, which imports a JSON bundle downloaded by `getkey_ext`.

Keep this extension disabled while registering with `getkey_ext`, since Chromium allows only one extension to own `webAuthenticationProxy` at a time. `getkey_ext` downloads the bundle and detaches after registration. Enable this extension and click **Add key** once to import the bundle. It attaches automatically for assertions. Every assertion opens a dialog where you choose a matching saved key or click **Add key** to import a bundle; the file chooser opens directly from that click.

The authenticator sets both UP and UV bits (`flags: 5`) to satisfy AgeKey's user-verification requirement. It does not perform a PIN, biometric, or other verification ceremony, so this is a compatibility workaround and does not provide real user verification. A relying party may still reject the credential if registration did not persist on its server; a local “create success” message or exported key does not prove server-side registration.
