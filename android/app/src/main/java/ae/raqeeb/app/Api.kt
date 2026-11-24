package ae.raqeeb.app

import android.content.Context
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Talks to the SAWNN server. Only message text the user received is sent, never contacts or call data. */
object Api {
    fun server(ctx: Context): String =
        ctx.getSharedPreferences("raqeeb", Context.MODE_PRIVATE).getString("server", BuildConfig.SERVER) ?: BuildConfig.SERVER

    fun setServer(ctx: Context, url: String) =
        ctx.getSharedPreferences("raqeeb", Context.MODE_PRIVATE).edit().putString("server", url.trimEnd('/')).apply()

    /** Returns the parsed /api/check-message result, or null when the server can't be reached. */
    fun checkMessage(ctx: Context, text: String): JSONObject? = try {
        val conn = URL("${server(ctx)}/api/check-message").openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.connectTimeout = 4000
        conn.readTimeout = 6000
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.outputStream.use { it.write(JSONObject().put("text", text).toString().toByteArray()) }
        val body = conn.inputStream.bufferedReader().use { it.readText() }
        JSONObject(body)
    } catch (e: Exception) {
        null
    }
}
