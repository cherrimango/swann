# RAQEEB Protect for Android

RAQEEB Protect runs in any phone browser at `/app` and can be installed as a PWA. This native shell adds what a web app can't do on Android:

| Feature | How it works | Android |
|---|---|---|
| Offline protection | `Protection.kt` downloads the signed protection package, verifies the Ed25519 signature against a pinned key, and keeps the rules on the phone. Expired rules are ignored. | Signature check needs 13+. Older phones use online checks only. |
| Scam call blocking | `ScamCallScreening.kt` rejects incoming calls from numbers analysts confirmed. The number is compared with the local list and never sent anywhere. | 10+, after the user makes RAQEEB the call-screening app |
| Message scanning | `RaqeebListener.kt` reads the text of new SMS, WhatsApp and Telegram notifications once the user grants Notification access. It checks links against the local rules first (this works offline), then asks the server about unknown links. | 8+ |
| UAE PASS guard | If a UAE PASS or bank approval notification arrives while a call is active, a full-screen stop opens. Only the call state is read, never numbers or audio. | 8+ |
| Share to RAQEEB | Share any message or link into the app to check it or report it. | 8+ |

## Build
1. Open the `android/` folder in Android Studio (Hedgehog or newer) and let Gradle sync.
2. Set your laptop's LAN address in `app/build.gradle.kts` (`SERVER`). You can also change it later from the app's first-run dialog.
3. Optional: pin the protection key at build time by adding `raqeebProtectionKey=<value from /api/protection/public-key>` to `~/.gradle/gradle.properties`. Without it, the key is pinned on first sync.
4. Run it on a phone. Grant Notification access, and accept the call-screening request.

### Release APK and AAB
Add these to `~/.gradle/gradle.properties`. Keep them out of the repository.
```
raqeebKeystore=/path/to/raqeeb.jks
raqeebKeystorePassword=…
raqeebKeyAlias=raqeeb
raqeebKeyPassword=…
```
- APK: `./gradlew assembleRelease` produces `app/build/outputs/apk/release/`.
- AAB: `./gradlew bundleRelease` produces `app/build/outputs/bundle/release/`.

Before a store release:
- Serve RAQEEB over HTTPS only and set `cleartextTrafficPermitted="false"` in `res/xml/network_security_config.xml`.
- Replace the placeholder icon.
- Complete the Play Store declarations for notification-listener and call-screening use.

## Honest status
This module was written for the hackathon. It has **not been compiled**: the environment it was written in has no Android SDK. Expect small fixes when Android Studio syncs. For example, it may ask you to upgrade the Gradle plugin versions in `build.gradle.kts`.

The web app (`/app`) is the tested client. It has the same features, apart from call blocking and notification scanning, which only Android allows.
