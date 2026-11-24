package ae.raqeeb.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.telephony.TelephonyManager
import androidx.core.app.NotificationCompat
import java.util.concurrent.Executors

/**
 * Watches incoming notifications.
 *  1. Messages (SMS, WhatsApp, Telegram) that contain a link are checked by SAWNN; scams raise an alert.
 *  2. UAE PASS or bank approval notifications that arrive DURING A CALL open the full-screen guard.
 */
class RaqeebListener : NotificationListenerService() {
    private val pool = Executors.newSingleThreadExecutor()
    private val recent = LinkedHashSet<String>()

    private val messagingApps = setOf(
        "com.google.android.apps.messaging", "com.samsung.android.messaging", "com.android.mms",
        "com.whatsapp", "com.whatsapp.w4b", "org.telegram.messenger",
    )

    // Approval-style notifications. Package names vary by app version, so text cues are matched too.
    private val approvalPackages = setOf("ae.uaepass.mainapp")
    private val approvalCues = listOf("uae pass", "uaepass", "approve", "login request", "sign in request", "الهوية الرقمية", "طلب تسجيل دخول", "موافقة")

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val extras = sbn.notification.extras
        val text = listOfNotNull(
            extras.getCharSequence("android.title")?.toString(),
            extras.getCharSequence("android.text")?.toString(),
            extras.getCharSequence("android.bigText")?.toString(),
        ).joinToString(" ").trim()
        if (text.isEmpty()) return

        if (isApproval(sbn.packageName, text) && inCall()) {
            startActivity(Intent(this, GuardActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            return
        }
        if (sbn.packageName in messagingApps && LINK.containsMatchIn(text) && recent.add(text)) {
            if (recent.size > 50) recent.remove(recent.first())
            pool.execute { check(text) }
        }
    }

    override fun onListenerConnected() {
        pool.execute { Protection.sync(this, force = true) }
    }

    private fun isApproval(pkg: String, text: String): Boolean {
        val low = text.lowercase()
        return pkg in approvalPackages || approvalCues.count { low.contains(it) } >= 2
    }

    private fun inCall(): Boolean {
        val tm = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        return try {
            @Suppress("DEPRECATION")
            tm.callState != TelephonyManager.CALL_STATE_IDLE
        } catch (e: SecurityException) {
            false
        }
    }

    private fun check(text: String) {
        Protection.sync(this)
        // 1. Published SAWNN rules on the phone: works offline and needs no server round trip.
        LINK.findAll(text).map { it.value }.firstNotNullOfOrNull { Protection.matchLink(this, it) }?.let { rule ->
            alert("Blocked scam link", "This message links to ${rule.value}, a confirmed scam" +
                (if (rule.brand.isNotEmpty()) " pretending to be ${rule.brand}" else "") + ". Don’t open it.")
            return
        }
        // 2. Online analysis for links SAWNN hasn't seen yet.
        val r = Api.checkMessage(this, text) ?: return
        val verdict = r.optString("verdict")
        if (verdict != "scam" && verdict != "suspicious") return
        val link = r.optJSONArray("links")?.optJSONObject(0)
        val brand = link?.optJSONObject("impersonated_brand")?.optString("name").orEmpty()
        alert(
            if (verdict == "scam") "Scam message detected" else "Suspicious message",
            (if (brand.isNotEmpty()) "Pretends to be $brand. " else "") + r.optString("advice_en"),
        )
    }

    private fun alert(title: String, body: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Scam alerts", NotificationManager.IMPORTANCE_HIGH))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        nm.notify(
            (System.currentTimeMillis() % 100000).toInt(),
            NotificationCompat.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setContentIntent(open)
                .setAutoCancel(true)
                .build(),
        )
    }

    companion object {
        const val CHANNEL = "raqeeb_alerts"
        val LINK = Regex("""(https?://|www\.)\S+|\b[a-z0-9-]+\.(com|net|org|info|ae|top|xyz|shop|online|site|live|click|icu|cfd|sbs|vip|io|app|co|me)\b""", RegexOption.IGNORE_CASE)
    }
}
