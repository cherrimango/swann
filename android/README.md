# RAQEEB Android companion

The resident app (`/app`) runs in any phone browser. This native shell adds what a web app can't do:

- **Message scanning**: reads the text of new SMS / WhatsApp / Telegram notifications (after the user grants
  Notification access), sends message text with a link to the RAQEEB server, and raises an alert for scams.
- **UAE PASS guard**: when a UAE PASS or bank approval notification arrives *while a call is active*, it opens a
  full-screen stop. Only the call *state* is read, never numbers or audio.
- **Share to RAQEEB**: "Share" any message or link into the app to check it.

## Build
1. Open the `android/` folder in Android Studio (Hedgehog or newer), let Gradle sync.
2. Set your laptop's LAN address in `app/build.gradle.kts` (`SERVER`), or change it later in the app.
3. Run on a phone (Android 8+). Grant Notification access when asked.

Tested status: written for the hackathon and not yet compiled in CI. If Gradle complains about plugin versions,
let Android Studio upgrade them.
