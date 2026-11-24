# MIRA Protect on iOS: plan

Status: **plan only.** No iOS code has been written or built.

## Available today with no native code
- MIRA Protect (`/app`) installs from Safari with *Share → Add to Home Screen*.
- The installed app:
  - works offline, using the cached app shell and the cached signed protection package;
  - verifies the Ed25519 signature in the browser where WebKit supports it;
  - sends web push notifications on iOS 16.4 or later, for apps added to the Home Screen.
- Not available on iOS: QR scanning through `BarcodeDetector`. Users paste the link instead, or open the camera and choose *Share to MIRA*.

## Native app (SwiftUI), in order of value
| Feature | iOS API | Notes |
|---|---|---|
| Scam SMS filtering | **Message Filter extension** (`ILMessageFilterExtension`) | iOS sends unknown-sender SMS to the extension. The extension checks links against the local signed rules first, then may ask the MIRA server through the deferral network API. It sorts scams into *Junk*. It can't read iMessage from contacts or WhatsApp. |
| Scam call blocking | **Call Directory extension** (`CXCallDirectoryProvider`) | Loads confirmed scam numbers from the protection package into the system block list. It is refreshed when a new version is published. Numbers never leave the phone. |
| Link checking anywhere | **Share extension** and **Safari Web Extension** | The Share extension sends a message or link to MIRA. The Safari extension warns before a blocked domain loads. |
| DNS protection | **NEDNSProxyProvider** or a DNS settings profile (`NEDNSSettingsManager`) | Points DNS to the MIRA DNS shield over DoH. Needs a managed or supervised device, or a user-installed profile. |
| Report flow | SwiftUI and `PhotosPicker` | The same `/api/citizen/report` multipart API as the web app. |
| Signed rules | CryptoKit `Curve25519.Signing.PublicKey` | Verifies `signed_payload` against the pinned key before applying it, the same check the Android and web clients make. |

## What iOS does not allow
- **The UAE PASS guard as built on Android is not possible.** iOS gives apps no access to other apps' notifications. Instead, the app teaches the pattern, and a Live Activity reminder can be shown during calls the user starts from MIRA.
- **No WhatsApp or Telegram scanning.** Users share the message into MIRA instead.

## Steps
1. An Apple Developer account owned by the operating entity, plus App Group entitlements so the app and its extensions share the rules file.
2. Shared Swift package: API client, signed-rules store, canonical-JSON verification.
3. The app, then the Message Filter, Call Directory and Share extensions.
4. TestFlight with police staff, then an App Store review covering the privacy disclosures for SMS filtering.
