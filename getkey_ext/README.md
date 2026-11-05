# getkey_ext

This Chrome/Chromium MV3 extension automatically creates an ES256/P-256 key for AgeKey WebAuthn registration and downloads one JSON bundle containing the credential ID, user handle, RP ID, and PKCS#8 private key.

Disable `bypass_ext` while registering because Chromium permits only one extension to own `webAuthenticationProxy`. Load or enable this extension, visit AgeKey, and start registration. After delivering the create response, it detaches and downloads the bundle. Then enable `bypass_ext` and use its **Add key** button to import the bundle.

The registration response sets the UP and UV flags for AgeKey compatibility, but this software authenticator does not perform actual user verification. A response delivered to the page is not proof that AgeKey saved the credential server-side; confirm the site's registration result before relying on assertions.
