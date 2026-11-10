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
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.irpair.ScanQr

fun store(c: Context) = File(c.filesDir, "pasa")

sealed interface Screen {
    data object List : Screen
    data class Entry(val name: String) : Screen
    data class Edit(val name: String) : Screen
}

class MainActivity : ComponentActivity() {
    private var handle by mutableStateOf(0L)

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (android.os.Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        setContent { MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) { App() } }
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) lock()
    }

    private fun lock() {
        if (handle != 0L) Native.close(handle)
        handle = 0
    }

    private fun copy(text: String) {
        val cm = getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText("pasa", text)
        clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
        cm.setPrimaryClip(clip)
        Handler(Looper.getMainLooper()).postDelayed({ cm.clearPrimaryClip() }, 45_000)
    }

    @Composable
    private fun App() {
        val dir = store(this).path
        var err by remember { mutableStateOf("") }
        var busy by remember { mutableStateOf(false) }
        val scope = rememberCoroutineScope()
        fun go(f: suspend () -> Unit) = scope.launch {
            busy = true
            err = runCatching { f() }.exceptionOrNull()?.message?.removePrefix("Rust error: ") ?: ""
            busy = false
        }
        Scaffold { pad ->
            Column(Modifier.padding(pad).padding(16.dp).fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                if (err.isNotEmpty()) Text(err, color = MaterialTheme.colorScheme.error)
                when {
                    !File(dir, "key").exists() -> Setup(dir, ::go)
                    handle == 0L -> Unlock(dir, ::go)
                    else -> Store(dir, ::go)
                }
            }
        }
    }

    @Composable
    private fun Setup(dir: String, go: (suspend () -> Unit) -> Unit) {
        var name by remember { mutableStateOf("home") }
        var code by remember { mutableStateOf("") }
        var pw by remember { mutableStateOf("") }
        val scan = rememberLauncherForActivityResult(ScanQr()) { it?.let { t -> code = t } }
        Text("Join a device: on it, run pasa pair phone", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(name, { name = it }, label = { Text("Its name") }, singleLine = true)
        OutlinedTextField(code, { code = it }, label = { Text("Code") }, singleLine = true)
        TextButton({ scan.launch(Unit) }) { Text("Scan a QR code") }
        Secret(pw, { pw = it }, "Pairing password")
        Text("Joining turns sync on: the phone then reaches your devices through the relay.")
        Button({
            go {
                withContext(Dispatchers.IO) { Native.join(dir, name, code.trim(), pw) }
                setSync(true)
            }
        }) { Text("Join") }
        HorizontalDivider()
        var npw by remember { mutableStateOf("") }
        Secret(npw, { npw = it }, "Or a new store's password")
        Button({ go { handle = withContext(Dispatchers.IO) { Native.open(dir, npw.toByteArray(), null, null, true) } } }) { Text("New store") }
    }

    @Composable
    private fun Unlock(dir: String, go: (suspend () -> Unit) -> Unit) {
        var pw by remember { mutableStateOf("") }
        val chal = remember { Native.challenge(dir) }
        Secret(pw, { pw = it }, "Password")
        if (chal != null) Text("Then hold your YubiKey to the phone")
        Button({
            go {
                val r = chal?.let { yubikey(this, it) }
                handle = withContext(Dispatchers.IO) { Native.open(dir, pw.toByteArray(), null, r, false) }
                pw = ""
                if (syncOn(this)) withContext(Dispatchers.IO) { Native.sync(dir, false) }
            }
        }) { Text("Unlock") }
    }

    @Composable
    private fun Store(dir: String, go: (suspend () -> Unit) -> Unit) {
        var screen by remember { mutableStateOf<Screen>(Screen.List) }
        var names by remember { mutableStateOf(listOf<String>()) }
        var tick by remember { mutableStateOf(0) }
        val reload = { tick++ }
        LaunchedEffect(handle, tick) {
            names = withContext(Dispatchers.IO) { Native.names(handle) }.lines().filter { it.isNotEmpty() }
        }
        val io = { f: () -> Unit -> go { withContext(Dispatchers.IO) { f() }; reload() } }
        val after = { f: () -> Unit ->
            go {
                withContext(Dispatchers.IO) { f(); if (syncOn(this@MainActivity)) Native.sync(dir, true) }
                reload()
            }
        }
        when (val s = screen) {
            Screen.List -> {
                var q by remember { mutableStateOf("") }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button({ screen = Screen.Edit("") }) { Text("New") }
                    OutlinedButton({ lock() }) { Text("Lock") }
                    var on by remember { mutableStateOf(syncOn(this@MainActivity)) }
                    Text("Sync", Modifier.align(Alignment.CenterVertically))
                    Switch(on, { on = it; setSync(it) })
                    if (on) OutlinedButton({ io { Native.sync(dir, false) } }) { Text("Now") }
                }
                OutlinedTextField(q, { q = it }, label = { Text("Search") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                LazyColumn {
                    items(names.filter { it.contains(q, ignoreCase = true) }) {
                        Text(it, Modifier.fillMaxWidth().clickable { screen = Screen.Entry(it) }.padding(vertical = 12.dp))
                    }
                }
            }
            is Screen.Entry -> {
                var body by remember(s) { mutableStateOf("") }
                LaunchedEffect(s) { body = withContext(Dispatchers.IO) { runCatching { Native.get(handle, s.name) }.getOrDefault("") } }
                var shown by remember { mutableStateOf(false) }
                var sure by remember { mutableStateOf(false) }
                Text(s.name, style = MaterialTheme.typography.titleLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    for (f in listOf("pass", "user", "otp")) {
                        val v = Native.field(body, f)
                        if (v.isNotEmpty()) OutlinedButton({ copy(v) }) { Text("Copy $f") }
                    }
                }
                Text(if (shown) body else body.substringAfter('\n', ""), fontFamily = FontFamily.Monospace,
                    modifier = Modifier.verticalScroll(rememberScrollState()).clickable { shown = !shown })
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button({ screen = Screen.Edit(s.name) }) { Text("Edit") }
                    OutlinedButton({
                        if (sure) { after { Native.put(handle, s.name, "") }; screen = Screen.List } else sure = true
                    }) { Text(if (sure) "Delete: sure?" else "Delete") }
                    TextButton({ screen = Screen.List }) { Text("Back") }
                }
            }
            is Screen.Edit -> {
                var name by remember { mutableStateOf(s.name) }
                var body by remember { mutableStateOf("") }
                LaunchedEffect(s) { if (s.name.isNotEmpty()) body = withContext(Dispatchers.IO) { Native.get(handle, s.name) } }
                OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(body, { body = it }, label = { Text("Password, then key: value lines") },
                    textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace), modifier = Modifier.fillMaxWidth().heightIn(min = 240.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton({ body = Native.generate(24) + "\n" + body.substringAfter('\n', "") }) { Text("Generate") }
                    Button({
                        val (old, new, b) = Triple(s.name, name, body)
                        after { Native.put(handle, new, b); if (old.isNotEmpty() && old != new) Native.put(handle, old, "") }
                        screen = Screen.Entry(name)
                    }, enabled = name.isNotBlank() && body.isNotEmpty()) { Text("Save") }
                    TextButton({ screen = Screen.List }) { Text("Cancel") }
                }
            }
        }
    }

    private fun setSync(on: Boolean) {
        getSharedPreferences("pasa", 0).edit().putBoolean("sync", on).apply()
        if (on) push(this)
    }

    @Composable
    private fun Secret(v: String, set: (String) -> Unit, label: String) =
        OutlinedTextField(v, set, label = { Text(label) }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
}
