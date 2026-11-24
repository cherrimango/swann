package ae.raqeeb.app

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Full-screen stop shown when a UAE PASS / bank approval arrives during a call. */
class GuardActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        getSystemService(Vibrator::class.java)?.vibrate(VibrationEffect.createWaveform(longArrayOf(0, 300, 120, 300, 120, 300), -1))

        val pad = (24 * resources.displayMetrics.density).toInt()
        fun text(s: String, size: Float, bold: Boolean = false, rtl: Boolean = false) = TextView(this).apply {
            this.text = s
            textSize = size
            setTextColor(Color.parseColor("#FBF7F0"))
            if (bold) typeface = Typeface.DEFAULT_BOLD
            gravity = if (rtl) Gravity.END else Gravity.START
            setPadding(0, pad / 3, 0, pad / 3)
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(Color.parseColor("#9C3A14"))
            setPadding(pad, pad * 2, pad, pad)
            addView(text("SAWNN stopped an approval", 16f))
            addView(text("Someone is trying to log in as you.", 34f, bold = true))
            addView(text("شخص ما يحاول تسجيل الدخول باسمك.", 28f, bold = true, rtl = true))
            addView(text("You’re on a call and an approval request just arrived. Real officials never ask you to approve a login. Hang up first.", 18f))
            addView(Button(this@GuardActivity).apply {
                text = "I didn’t ask for this. Decline"
                setOnClickListener { finish() }
            })
            addView(Button(this@GuardActivity).apply {
                text = "It was me"
                setOnClickListener { finish() }
            })
        }
        setContentView(root)
    }
}
