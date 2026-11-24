package ae.raqeeb.app

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Offline protection: downloads the signed MIRA protection package, verifies its Ed25519 signature, and keeps the
 * rules on the phone so scam sites and numbers are caught without a connection. Expired rules are ignored.
 *
 * The server's public key is pinned on first sync (or set at build time in BuildConfig.PROTECTION_KEY); a package
 * signed by any other key is rejected and the previous rules stay in force.
 */
object Protection {
    private const val PREFS = "raqeeb_protection"
    private const val MIN_SYNC_MS = 15 * 60 * 1000L
    private val X509_ED25519_PREFIX = "302a300506032b6570032100".chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    data class Rule(val type: String, val value: String, val brand: String, val expires: Long)

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun get(url: String): JSONObject {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 4000
        conn.readTimeout = 8000
        return JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
    }

    /** Fetch and apply the latest package. Returns the applied version, or null if nothing changed or it failed. */
    fun sync(ctx: Context, force: Boolean = false): Int? {
        val p = prefs(ctx)
        if (!force && System.currentTimeMillis() - p.getLong("synced", 0) < MIN_SYNC_MS) return null
        return try {
            val server = Api.server(ctx)
            val pkg = get("$server/api/protection/latest")
            val signed = pkg.getString("signed_payload")
            val pinned = BuildConfig.PROTECTION_KEY.ifEmpty { p.getString("key", null) }
                ?: get("$server/api/protection/public-key").getString("public_key").also { p.edit().putString("key", it).apply() }
            if (!verify(signed, pkg.getString("signature"), pinned)) return null
            val payload = JSONObject(signed)
            val version = payload.getInt("version")
            p.edit().putString("rules", payload.getJSONArray("rules").toString()).putInt("version", version)
                .putLong("synced", System.currentTimeMillis()).apply()
            version
        } catch (e: Exception) {
            null  // offline: keep the rules we already have
        }
    }

    private fun verify(signed: String, signatureB64: String, keyB64: String): Boolean = try {
        val raw = Base64.decode(keyB64, Base64.DEFAULT)
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(X509_ED25519_PREFIX + raw))
        Signature.getInstance("Ed25519").run {
            initVerify(key)
            update(signed.toByteArray(Charsets.UTF_8))
            verify(Base64.decode(signatureB64, Base64.DEFAULT))
        }
    } catch (e: Exception) {
        false  // Ed25519 needs Android 13+; older phones fall back to online checks only
    }

    fun version(ctx: Context): Int = prefs(ctx).getInt("version", 0)

    fun rules(ctx: Context): List<Rule> {
        val arr = JSONArray(prefs(ctx).getString("rules", "[]"))
        val now = System.currentTimeMillis() / 1000
        return (0 until arr.length()).map { arr.getJSONObject(it) }
            .map { Rule(it.getString("type"), it.getString("value"), it.optString("brand"), it.optLong("expires", 0)) }
            .filter { it.expires == 0L || it.expires > now }
    }

    /** Is this link covered by a published rule? URL rules match by prefix; domain and host rules match subdomains. */
    fun matchLink(ctx: Context, link: String): Rule? {
        val clean = link.trim().removePrefix("https://").removePrefix("http://").removePrefix("www.").lowercase()
        val host = clean.substringBefore('/').substringBefore('?').substringBefore(':')
        return rules(ctx).firstOrNull { r ->
            when (r.type) {
                "url" -> clean.trimEnd('/').startsWith(r.value)
                "domain", "host" -> host == r.value || host.endsWith("." + r.value)
                else -> false
            }
        }
    }

    /** Is this phone number a confirmed scam number? Compares the last 9 digits (UAE numbers without the 0 / +971). */
    fun matchPhone(ctx: Context, number: String): Rule? {
        val digits = number.filter { it.isDigit() }
        if (digits.length < 7) return null
        val tail = digits.takeLast(9)
        return rules(ctx).firstOrNull { it.type == "phone" && it.value.filter { c -> c.isDigit() }.endsWith(tail) }
    }
}
