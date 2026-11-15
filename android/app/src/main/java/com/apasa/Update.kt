package com.apasa

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** Updates: the newest release's APK (GitHub releases), checked against its
 *  `.sha256` there, installed by Android's package installer, which takes an
 *  update only signed by the installed app's own key: a file from anyone
 *  else does not install, whatever the server hands out. */
object Update {
    private const val RELEASES = "https://github.com/cablab-ucf/pasa/releases"
    private const val MOST = 200L shl 20

    private fun open(url: String, follow: Boolean = true) =
        (URL(url).openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = follow
            connectTimeout = 15_000
            readTimeout = 30_000
        }

    /** The newest release's version ("0.4.18"), from where `latest` leads. */
    fun latest(): String? {
        val c = open("$RELEASES/latest", follow = false)
        try {
            c.requestMethod = "HEAD"
            c.responseCode
            val v = c.getHeaderField("Location")?.substringAfterLast("/tag/v", "")
            return v?.takeIf { Regex("[0-9]+(\\.[0-9]+)*").matches(it) }
        } finally {
            c.disconnect()
        }
    }

    /** Whether version [v] is newer than [than]. */
    fun newer(than: String, v: String): Boolean {
        val n = { s: String -> s.split('.').map { it.toIntOrNull() ?: 0 } }
        val (a, b) = n(v) to n(than)
        for (i in 0 until maxOf(a.size, b.size)) {
            val d = a.getOrElse(i) { 0 } - b.getOrElse(i) { 0 }
            if (d != 0) return d > 0
        }
        return false
    }

    /** Release [v]'s APK, into [dir], its SHA-256 the release's. */
    fun fetch(dir: File, v: String): File {
        val name = "apasa-v$v.apk"
        val at = "$RELEASES/download/v$v/$name"
        val want = open("$at.sha256").inputStream.bufferedReader().use { it.readLine() ?: "" }
            .trim().substringBefore(' ').lowercase()
        require(Regex("[0-9a-f]{64}").matches(want)) { "$name: no hash in the release" }
        dir.mkdirs()
        val (f, part) = File(dir, name) to File(dir, "$name.part")
        val md = MessageDigest.getInstance("SHA-256")
        open(at).inputStream.use { i ->
            part.outputStream().use { o ->
                val b = ByteArray(1 shl 16)
                var n = 0L
                while (true) {
                    val r = i.read(b)
                    if (r < 0) break
                    n += r
                    require(n <= MOST) { "$name: too large" }
                    md.update(b, 0, r)
                    o.write(b, 0, r)
                }
            }
        }
        if (md.digest().joinToString("") { "%02x".format(it) } != want) {
            part.delete()
            error("$name: not the file the release names")
        }
        part.renameTo(f)
        return f
    }

    /** [f] installed by the package installer: from Android 12 on with no
     *  prompt (an app updating itself), once the app may install apps. The
     *  app closes as it is replaced. */
    fun install(c: Context, f: File) {
        val pm = c.packageManager
        runCatching {
            val p = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            p.setAppPackageName(c.packageName)
            if (Build.VERSION.SDK_INT >= 31) {
                p.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }
            val id = pm.packageInstaller.createSession(p)
            pm.packageInstaller.openSession(id).use { s ->
                s.openWrite("apasa.apk", 0, f.length()).use { out ->
                    f.inputStream().use { it.copyTo(out) }
                    s.fsync(out)
                }
                // Mutable: the installer adds its answer to it.
                val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                val done = Intent(c, Installed::class.java)
                s.commit(PendingIntent.getBroadcast(c, id, done, flags).intentSender)
            }
        }
        f.delete()
    }
}

/** The package installer's answer: its prompt shown when it asks one (an
 *  update before Android 12), a failure said. */
class Installed : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        when (i.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_SUCCESS -> Unit
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val ask = i.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
                runCatching { c.startActivity(ask.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
            }
            else -> android.widget.Toast.makeText(
                c,
                "Update failed: " + (i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "?"),
                android.widget.Toast.LENGTH_LONG,
            ).show()
        }
    }
}
