package ae.raqeeb.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import android.telecom.Call
import android.telecom.CallScreeningService
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat

/**
 * Rejects incoming calls from numbers that SAWNN analysts confirmed as scam numbers (from the signed protection
 * package stored on the phone), and tells the user why. Works offline. Only the incoming number is compared with the
 * local list; it is never sent anywhere. Requires the user to make SAWNN the call-screening app (Android 10+).
 */
@RequiresApi(Build.VERSION_CODES.Q)
class ScamCallScreening : CallScreeningService() {
    override fun onScreenCall(details: Call.Details) {
        val number = details.handle?.schemeSpecificPart.orEmpty()
        val rule = if (details.callDirection == Call.Details.DIRECTION_INCOMING) Protection.matchPhone(this, number) else null
        val response = CallResponse.Builder()
        if (rule != null) {
            response.setDisallowCall(true).setRejectCall(true).setSkipCallLog(false).setSkipNotification(true)
            notifyBlocked(number)
        }
        respondToCall(details, response.build())
    }

    private fun notifyBlocked(number: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(RaqeebListener.CHANNEL, "Scam alerts", NotificationManager.IMPORTANCE_HIGH))
        nm.notify(
            number.hashCode(),
            NotificationCompat.Builder(this, RaqeebListener.CHANNEL)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("SAWNN blocked a scam call")
                .setContentText("$number is a confirmed scam number. حظر صون مكالمة احتيالية.")
                .setAutoCancel(true)
                .build(),
        )
    }
}
