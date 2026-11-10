package com.apasa

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.File
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.pairir.ScanQr

fun store(c: Context) = File(c.filesDir, "pasa")

private suspend fun <T> io(f: () -> T): T = withContext(Dispatchers.IO) { f() }
private fun lines(s: String) = s.lines().filter { it.isNotEmpty() }

/** The screens are [Pasa] (Ui.kt); this is what they ask of the phone. */
class MainActivity : ComponentActivity(), Host {
    private var handle by mutableStateOf(0L)
    private var stored by mutableStateOf(false)
    private val nav = Nav()
    private val dir get() = store(this).path
    private var scanned: (String) -> Unit = {}
    private val scanner = registerForActivityResult(ScanQr()) { it?.let { t -> scanned(t) } }

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        enableEdgeToEdge()
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (android.os.Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        stored = File(dir, "key").exists()
        setContent {
            BackHandler(enabled = !nav.atTop) { nav.back() }
            Pasa(this, nav)
        }
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) lock()
    }

    override val hasStore get() = stored
    override val needsKey get() = Native.challenge(dir) != null
    override val open get() = handle != 0L
    override val version get() = packageManager.getPackageInfo(packageName, 0).versionName ?: ""

    override var sync
        get() = syncOn(this)
        set(on) {
            getSharedPreferences("pasa", 0).edit().putBoolean("sync", on).apply()
            if (on) push(this)
        }

    override suspend fun create(pw: String, key: Boolean) {
        val c = if (key) ByteArray(32).also { SecureRandom().nextBytes(it) } else null
        val r = c?.let { yubikey(this, it) }
        handle = io { Native.open(dir, pw.toByteArray(), c, r, true) }
        stored = true
    }

    override suspend fun unlock(pw: String) {
        val r = Native.challenge(dir)?.let { yubikey(this, it) }
        handle = io { Native.open(dir, pw.toByteArray(), null, r, false) }
        if (sync) io { runCatching { Native.sync(dir, false) } }
    }

    /** Joining turns sync on: the phone then reaches its devices through the relay. */
    override suspend fun join(name: String, code: String, pw: String) {
        io { Native.join(dir, name, code, pw) }
        sync = true
        stored = true
    }

    override fun scan(got: (String) -> Unit) {
        scanned = got
        scanner.launch(Unit)
    }

    override fun lock() {
        if (handle != 0L) Native.close(handle)
        handle = 0
        nav.screen = Screen.List
    }

    override suspend fun names() = io { lines(Native.names(handle)) }
    override suspend fun get(name: String) = io { Native.get(handle, name) }

    override suspend fun put(name: String, body: String) = io {
        Native.put(handle, name, body)
        if (sync) runCatching { Native.sync(dir, true) }
        Unit
    }

    override fun form(body: String) = Native.form(body).split('\u001f', limit = 5).let {
        Form(it[0], it.getOrElse(1) { "" }, it.getOrElse(2) { "" }, it.getOrElse(3) { "" }, it.getOrElse(4) { "" })
    }

    override fun text(f: Form) = Native.text(listOf(f.pass, f.user, f.url, f.otp, f.notes).joinToString("\u001f"))
    override fun code(body: String) = Native.field(body, "otp")
    override fun generate(len: Int, symbols: Boolean) = Native.generate(len, symbols)

    override fun copy(text: String) {
        val cm = getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText("pasa", text)
        clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
        cm.setPrimaryClip(clip)
        Handler(Looper.getMainLooper()).postDelayed({ cm.clearPrimaryClip() }, 45_000)
    }

    override suspend fun syncNow() = io { Native.sync(dir, false) }
    override suspend fun peers() = io { lines(Native.peers(dir)) }
    override suspend fun forget(name: String) = io { Native.forget(dir, name) }
    override suspend fun pair(name: String) = io { lines(Native.pair(handle, name)).let { it[0] to it[1] } }
}
