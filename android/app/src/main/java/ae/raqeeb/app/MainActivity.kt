package ae.raqeeb.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.AlertDialog
import android.app.role.RoleManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat

/** Hosts the SAWNN resident app and asks once for the two permissions the native guard needs. */
class MainActivity : AppCompatActivity() {
    private lateinit var web: WebView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            webViewClient = WebViewClient()
        }
        setContentView(web)
        load(intent)
        askPermissions()
        Thread { Protection.sync(this, force = true) }.start()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        load(intent)
    }

    private fun load(intent: Intent?) {
        val shared = intent?.takeIf { it.action == Intent.ACTION_SEND }?.getStringExtra(Intent.EXTRA_TEXT)
        val section = intent?.getStringExtra(EXTRA_SECTION)?.takeIf { it in setOf("quick", "report", "ask") }
        val url = "${Api.server(this)}/app" + (shared?.let { "?text=" + Uri.encode(it) } ?: "") + (section?.let { "#$it" } ?: "")
        web.loadUrl(url)
    }

    companion object {
        const val EXTRA_SECTION = "ae.raqeeb.app.SECTION"
    }

    private fun askPermissions() {
        val perms = mutableListOf(Manifest.permission.READ_PHONE_STATE)
        if (Build.VERSION.SDK_INT >= 33) perms += Manifest.permission.POST_NOTIFICATIONS
        ActivityCompat.requestPermissions(this, perms.toTypedArray(), 1)

        // Android 10+: let SAWNN reject calls from confirmed scam numbers (the user approves this in a system dialog).
        if (Build.VERSION.SDK_INT >= 29) {
            val roles = getSystemService(RoleManager::class.java)
            if (roles.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING) && !roles.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)) {
                @Suppress("DEPRECATION")
                startActivityForResult(roles.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING), 2)
            }
        }

        val enabled = NotificationManagerCompat.getEnabledListenerPackages(this).contains(packageName)
        if (!enabled) {
            AlertDialog.Builder(this)
                .setTitle("Turn on scam scanning")
                .setMessage("SAWNN reads the text of new message notifications to spot scam links, and watches for UAE PASS approvals during calls. Nothing else is read, and only message text is checked.")
                .setPositiveButton("Open settings") { _, _ -> startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) }
                .setNeutralButton("Server address") { _, _ -> editServer() }
                .setNegativeButton("Later", null)
                .show()
        }
    }

    private fun editServer() {
        val input = EditText(this).apply { setText(Api.server(this@MainActivity)) }
        AlertDialog.Builder(this)
            .setTitle("SAWNN server")
            .setView(input)
            .setPositiveButton("Save") { _, _ -> Api.setServer(this, input.text.toString()); load(null) }
            .show()
    }

}
