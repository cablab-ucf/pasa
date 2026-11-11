package com.apasa

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.provider.OpenableColumns
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
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

    /** A file is being picked: the store stays open under the picker. */
    private var picking = false
    private var picked: (Uri?) -> Unit = {}
    private val opener = registerForActivityResult(ActivityResultContracts.OpenDocument()) { picking = false; picked(it) }
    private val saver = registerForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { picking = false; picked(it) }

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        enableEdgeToEdge()
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (android.os.Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        stored = File(dir, "key").exists()
        readQuick()
        setContent {
            BackHandler(enabled = !nav.atTop) { nav.back() }
            Pasa(this, nav)
        }
    }

    /** Read again each time the app comes back: NFC may have been switched meanwhile. */
    private var nfcIsOff by mutableStateOf(false)
    override val nfcOff get() = nfcIsOff

    override fun onResume() {
        super.onResume()
        nfcIsOff = nfcOff(this)
    }

    override fun nfcSettings() {
        runCatching { startActivity(Intent(android.provider.Settings.ACTION_NFC_SETTINGS)) }
    }

    override fun onStop() {
        super.onStop()
        keySecret?.fill(0)
        keySecret = null
        if (isChangingConfigurations || picking) return
        if (setting("lock") == 0) lock() else main.postDelayed(locker, setting("lock") * 1000L)
    }

    override fun onStart() {
        super.onStart()
        main.removeCallbacks(locker)
    }

    private val main = Handler(Looper.getMainLooper())
    private val locker = Runnable { lock() }

    // What Settings changes, kept on this phone: seconds, and for the theme a number.
    private val settings = mutableStateMapOf<String, Int>()
    private val usual = mapOf("clip" to 45, "lock" to 0, "theme" to 0)
    override fun setting(name: String) = settings.getOrPut(name) { getSharedPreferences("pasa", 0).getInt(name, usual[name] ?: 0) }
    override fun set(name: String, value: Int) {
        settings[name] = value
        getSharedPreferences("pasa", 0).edit().putInt(name, value).apply()
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

    private var quickNow by mutableStateOf<Boolean?>(null)
    override val quick get() = quickNow
    private fun readQuick() { quickNow = Native.quick(dir)?.let { it[32].toInt() == 1 }; readFido() }
    private fun fresh() = ByteArray(32).also { SecureRandom().nextBytes(it) }

    override suspend fun create(pw: String, key: Key, pin: String) {
        val c = if (key == Key.Both) fresh() else null
        val r = c?.let { yubikey(this, it, enroll = true) }
        val h = io { Native.open(dir, pw.toByteArray(), c, r, true) }
        if (key == Key.Quick) runCatching { quickOn(h, pin) }.onFailure { Native.close(h); File(dir, "key").delete(); throw it }
        handle = h
        stored = true
    }

    private suspend fun quickOn(h: Long, pin: String) {
        val c = fresh()
        val r = yubikey(this, c, enroll = true)
        io { Native.quickOn(h, pin.toByteArray(), c, r) }
        readQuick()
    }

    /** The secret of the key last set up, for a spare: kept until the app leaves the screen. */
    private var keySecret: ByteArray? = null

    override suspend fun setUpKey(spare: Boolean) {
        val secret = when {
            !spare -> ByteArray(20).also { SecureRandom().nextBytes(it) }
            else -> keySecret ?: throw Exception("The first key's secret is no longer here (the app left the screen): a spare cannot be made of it now.")
        }
        writeKey(this, secret)
        keySecret = secret
    }

    override suspend fun setQuick(pin: String?) {
        if (pin == null) Native.quickOff(dir) else quickOn(handle, pin)
        readQuick()
    }

    override suspend fun unlockQuick(pin: String) {
        val r = yubikey(this, Native.quick(dir)!!.copyOf(32))
        handle = io { Native.openQuick(dir, pin.toByteArray(), r) }
        if (sync) io { runCatching { Native.sync(dir, false) } }
    }

    // Security keys (FIDO2): how many open the store here, and whether a PIN goes with any.
    private var fidoNow by mutableStateOf(0 to false)
    override val fidoKeys get() = fidoNow.first
    override val fidoPin get() = fidoNow.second
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun fidoHere() = Native.fido(dir).lines().filter { it.isNotEmpty() }.let { l ->
        l.firstOrNull()?.let { salt -> hex(salt) to l.drop(1).map { k -> hex(k.substringBefore(' ')) to k.endsWith(" 1") } }
    }
    private fun readFido() { fidoNow = fidoHere()?.second.orEmpty().let { it.size to it.any { k -> k.second } } }

    override suspend fun fidoAdd(pin: String) {
        val salt = Native.fidoSalt(handle)
        val (cred, uv, secret) = fidoNew(this, salt, pin)
        io { Native.fidoAdd(handle, salt, cred, uv, secret) }
        secret.fill(0)
        readFido()
    }

    override suspend fun unlockFido(pin: String) {
        val (salt, keys) = fidoHere() ?: throw Exception("No security key opens this store")
        val (cred, secret) = fidoSecret(this, keys, salt, pin)
        handle = io { Native.openFido(dir, cred, secret) }
        secret.fill(0)
        if (sync) io { runCatching { Native.sync(dir, false) } }
    }

    override fun fidoOff() {
        Native.fidoOff(dir)
        readFido()
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

    /** A change, then the news to the other devices. */
    private suspend fun changed(f: () -> Unit) = io {
        f()
        if (sync) runCatching { Native.sync(dir, true) }
        Unit
    }

    override suspend fun put(name: String, body: String) = changed { Native.put(handle, name, body) }

    override fun form(body: String) = Native.form(body).split('\u001f', limit = 8).let {
        val at = { i: Int -> it.getOrElse(i) { "" } }
        Form(at(0), at(1), at(2), at(3), at(7), at(4), at(5), at(6))
    }

    private fun joined(f: Form) = listOf(f.pass, f.user, f.url, f.otp, f.tags, f.expires, f.more, f.notes).joinToString("\u001f")
    override fun text(f: Form) = Native.text(joined(f))
    override fun problem(f: Form) = Native.problem(joined(f))
    override fun strength(pw: String) = Native.strength(pw)

    override suspend fun times(name: String) = io {
        lines(Native.times(handle, name)).map { it.toLong() }.let { if (it.size == 2) it[0] to it[1] else null }
    }

    override suspend fun health() = io {
        val rows = lines(Native.health(handle)).map { it.split('\t') }
        Health(
            rows.filter { it[0] == "weak" }.map { it[1] to it[2].toInt() },
            rows.filter { it[0] == "reused" }.map { it.drop(1) },
            rows.filter { it[0] == "expired" }.map { it[1] },
        )
    }

    override suspend fun stats() = io { lines(Native.stats(handle)).map { it.substringBefore('\t') to it.substringAfter('\t') } }

    /** Only 5 hex digits of the password's SHA-1 leave the phone; the answer is padded. */
    override suspend fun pwned(pw: String) = io {
        val (sent, kept) = lines(Native.pwnedKey(pw))
        val c = URL("https://api.pwnedpasswords.com/range/$sent").openConnection() as HttpURLConnection
        c.setRequestProperty("Add-Padding", "true")
        c.connectTimeout = 15_000
        c.readTimeout = 15_000
        try { Native.pwnedCount(kept, c.inputStream.bufferedReader().readText()) } finally { c.disconnect() }
    }

    override fun open(url: String) {
        runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }
    override fun code(body: String) = Native.field(body, "otp")
    override fun generate(g: Gen) =
        if (g.words) Native.speakable(g.count, g.seps, g.leet) else Native.generate(g.len, g.symbols)

    override suspend fun remove(name: String) = changed { Native.remove(handle, name) }
    override suspend fun rename(from: String, to: String) = changed { Native.rename(handle, from, to) }

    override suspend fun history(name: String) = io {
        Native.history(handle, name).split('\u001e').filter { it.isNotEmpty() }.map {
            it.substringBefore('\u001f').toLong() to it.substringAfter('\u001f')
        }
    }

    override suspend fun files(name: String) = io { lines(Native.files(handle, name)) }

    override fun attach(name: String, done: (String) -> Unit) {
        picked = { uri ->
            if (uri != null) done(runCatching {
                val file = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                    ?.use { c -> if (c.moveToFirst()) c.getString(0) else null } ?: "file"
                val body = contentResolver.openInputStream(uri)!!.use { it.readBytes() }
                Native.keep(handle, "$name/.files/$file", body)
                "$file: kept with $name"
            }.getOrElse { it.message ?: "It failed" })
        }
        picking = true
        opener.launch(arrayOf("*/*"))
    }

    override fun save(name: String, file: String, done: (String) -> Unit) {
        picked = { uri ->
            if (uri != null) done(runCatching {
                contentResolver.openOutputStream(uri)!!.use { it.write(Native.bytes(handle, "$name/.files/$file")) }
                "$file: saved"
            }.getOrElse { it.message ?: "It failed" })
        }
        picking = true
        saver.launch(file)
    }

    override fun copy(text: String) {
        val cm = getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText("pasa", text)
        clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
        cm.setPrimaryClip(clip)
        main.postDelayed({ cm.clearPrimaryClip() }, setting("clip") * 1000L)
    }

    override suspend fun syncNow() = io { Native.sync(dir, false) }
    override suspend fun peers() = io { lines(Native.peers(dir)) }
    override suspend fun forget(name: String) = io { Native.forget(dir, name) }
    override suspend fun pair(name: String) = io { lines(Native.pair(handle, name)).let { it[0] to it[1] } }
}
