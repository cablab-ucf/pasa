package com.apasa

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** An entry as its form: the same fields the desktop window shows. */
data class Form(
    val pass: String = "", val user: String = "", val url: String = "",
    val otp: String = "", val notes: String = "",
)

/** How a password is made: characters, or words to say aloud (22 bits each). */
data class Gen(
    val words: Boolean = false, val len: Int = 24, val symbols: Boolean = true,
    val count: Int = 4, val hyphens: Boolean = false, val leet: Boolean = false,
) {
    val bits get() = if (words) 22 * count else (len * kotlin.math.log2(if (symbols) 80.0 else 62.0)).toInt()
}

/** What the screens ask of the app: the store, the clipboard, the key, the camera. */
interface Host {
    val hasStore: Boolean
    val needsKey: Boolean
    val open: Boolean
    val version: String
    var sync: Boolean
    suspend fun create(pw: String, key: Boolean)
    suspend fun unlock(pw: String)
    suspend fun join(name: String, code: String, pw: String)
    fun scan(got: (String) -> Unit)
    fun lock()
    suspend fun names(): List<String>
    suspend fun get(name: String): String
    suspend fun put(name: String, body: String)
    suspend fun remove(name: String)
    suspend fun rename(from: String, to: String)
    /** Each version of [name], newest first: when (ms) and its text. */
    suspend fun history(name: String): List<Pair<Long, String>>
    suspend fun files(name: String): List<String>
    /** Pick a file and keep it with [name]; [done] says how it went. */
    fun attach(name: String, done: (String) -> Unit)
    /** Write [name]'s file [file] where the user says. */
    fun save(name: String, file: String, done: (String) -> Unit)
    fun form(body: String): Form
    fun text(f: Form): String
    fun code(body: String): String
    fun generate(g: Gen): String
    fun copy(text: String)
    suspend fun syncNow(): String
    suspend fun peers(): List<String>
    suspend fun forget(name: String)
    /** A pairing code and its password, for the device called [name]. */
    suspend fun pair(name: String): Pair<String, String>
}

sealed interface Screen {
    data object List : Screen
    data class Entry(val name: String) : Screen
    data class Edit(val name: String) : Screen
    data class History(val name: String) : Screen
    data object Devices : Screen
    data object Settings : Screen
}

/** Where the app is; [back] says whether it had somewhere to go back to. */
class Nav {
    var screen by mutableStateOf<Screen>(Screen.List)
    var joining by mutableStateOf(false)
    var gen by mutableStateOf(Gen())
    val atTop get() = screen == Screen.List && !joining

    fun back() {
        screen = when (val s = screen) {
            is Screen.Edit -> if (s.name.isEmpty()) Screen.List else Screen.Entry(s.name)
            is Screen.History -> Screen.Entry(s.name)
            else -> Screen.List
        }
        joining = false
    }
}

// The colours the desktop window uses.
private val Dark = darkColorScheme(
    primary = Color(0xFF5FB89A), onPrimary = Color(0xFF06281E),
    background = Color(0xFF101512), onBackground = Color(0xFFE6ECE8),
    surface = Color(0xFF18201C), onSurface = Color(0xFFE6ECE8),
    surfaceVariant = Color(0xFF18201C), onSurfaceVariant = Color(0xFF9AA8A1),
    surfaceContainer = Color(0xFF18201C), surfaceContainerHigh = Color(0xFF1E2823),
    surfaceContainerHighest = Color(0xFF1E2823),
    outline = Color(0xFF3A4741), outlineVariant = Color(0xFF2A3530),
    error = Color(0xFFF2877B), primaryContainer = Color(0xFF5FB89A), onPrimaryContainer = Color(0xFF06281E),
)
private val Light = lightColorScheme(
    primary = Color(0xFF2E5E4E), onPrimary = Color.White,
    background = Color(0xFFF6F8F6), onBackground = Color(0xFF17201B),
    surface = Color.White, onSurface = Color(0xFF17201B),
    surfaceVariant = Color.White, onSurfaceVariant = Color(0xFF5C6B63),
    surfaceContainer = Color.White, surfaceContainerHigh = Color(0xFFEDF1EE),
    surfaceContainerHighest = Color(0xFFEDF1EE),
    outline = Color(0xFFB9C4BE), outlineVariant = Color(0xFFD5DDD8),
    error = Color(0xFFB3261E), primaryContainer = Color(0xFF2E5E4E), onPrimaryContainer = Color.White,
)

private val muted @Composable get() = MaterialTheme.colorScheme.onSurfaceVariant
private val mono = FontFamily.Monospace

@Composable
fun Pasa(host: Host, nav: Nav, dark: Boolean = isSystemInDarkTheme()) {
    MaterialTheme(colorScheme = if (dark) Dark else Light) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Box(Modifier.safeDrawingPadding()) {
                when {
                    host.open -> Store(host, nav)
                    host.hasStore -> Unlock(host)
                    nav.joining -> Join(host, nav)
                    else -> Create(host, nav)
                }
            }
        }
    }
}

/** Runs [f], busy meanwhile; what went wrong, in the app's words. */
@Composable
private fun rememberJob(): Triple<Boolean, String, (suspend () -> Unit) -> Unit> {
    var busy by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    return Triple(busy, err) { f ->
        scope.launch {
            busy = true
            err = runCatching { f() }.exceptionOrNull()?.message?.removePrefix("Rust error: ") ?: ""
            busy = false
        }
    }
}

@Composable
private fun Label(t: String) = Text(t, style = MaterialTheme.typography.labelMedium, color = muted)

@Composable
private fun Field(
    v: String, set: (String) -> Unit, label: String, secret: Boolean = false,
    lines: Int = 1, trailing: (@Composable () -> Unit)? = null,
) = OutlinedTextField(
    v, set, label = { Text(label) }, singleLine = lines == 1, minLines = lines,
    visualTransformation = if (secret) PasswordVisualTransformation() else VisualTransformation.None,
    keyboardOptions = if (secret) KeyboardOptions(keyboardType = KeyboardType.Password) else KeyboardOptions.Default,
    trailingIcon = trailing, shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth(),
)

@Composable
private fun Primary(text: String, enabled: Boolean = true, go: () -> Unit) =
    Button(go, enabled = enabled, shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth().height(48.dp)) {
        Text(text, fontWeight = FontWeight.SemiBold)
    }

/** The name, one card in the middle for what the app wants first, and the other way in, small, in the corner. */
@Composable
private fun Front(
    title: String, busy: Boolean, err: String, ask: String = "", link: String = "",
    other: () -> Unit = {}, body: @Composable () -> Unit,
) = Box(Modifier.fillMaxSize().padding(20.dp)) {
    Column(
        Modifier.align(Alignment.TopCenter).widthIn(max = 420.dp).verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(56.dp))
        Text("pasa", fontSize = 40.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
        Text("A small password store", color = muted)
        Spacer(Modifier.height(24.dp))
        Column(
            Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface, RoundedCornerShape(16.dp))
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(16.dp)).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleLarge)
            body()
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (err.isNotEmpty()) Text(err, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.height(64.dp))
    }
    if (link.isNotEmpty()) Row(Modifier.align(Alignment.BottomEnd), verticalAlignment = Alignment.CenterVertically) {
        Text(ask, style = MaterialTheme.typography.bodySmall, color = muted)
        TextButton(other, contentPadding = PaddingValues(horizontal = 8.dp)) { Text(link) }
    }
}

@Composable
private fun Create(host: Host, nav: Nav) {
    var pw by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    var key by remember { mutableStateOf(false) }
    val (busy, err, go) = rememberJob()
    val differ = again.isNotEmpty() && pw != again
    Front(
        "Create your store", busy, if (differ) "The passwords differ" else err,
        "A store on another device already?", "Join it", { nav.joining = true },
    ) {
        Field(pw, { pw = it }, "Password", secret = true)
        Field(again, { again = it }, "Password, again", secret = true)
        Row(Modifier.fillMaxWidth().clickable { key = !key }, verticalAlignment = Alignment.CenterVertically) {
            Checkbox(key, { key = it })
            Column {
                Text("Require a hardware key (YubiKey)")
                Text(
                    "Its answer joins the password in the lock: the store then opens only with both.",
                    style = MaterialTheme.typography.bodySmall, color = muted,
                )
            }
        }
        if (key && busy) Text("Hold your YubiKey to the phone", color = MaterialTheme.colorScheme.primary)
        Primary("Create store", enabled = pw.isNotEmpty() && pw == again && !busy) { go { host.create(pw, key) } }
    }
}

@Composable
private fun Join(host: Host, nav: Nav) {
    var name by remember { mutableStateOf("home") }
    var code by remember { mutableStateOf("") }
    var pw by remember { mutableStateOf("") }
    val (busy, err, go) = rememberJob()
    Front("Join a store", busy, err, "No store yet?", "Create one", { nav.joining = false }) {
        Text(
            "On the device that has it: Devices, Add a device (or pasa pair NAME). It shows a code and a password.",
            style = MaterialTheme.typography.bodySmall, color = muted,
        )
        Field(name, { name = it }, "A name for that device")
        Field(code, { code = it }, "Code") { TextButton({ host.scan { code = it } }) { Text("Scan") } }
        Field(pw, { pw = it }, "Pairing password", secret = true)
        Primary("Join", enabled = name.isNotBlank() && code.isNotBlank() && !busy) { go { host.join(name.trim(), code.trim(), pw) } }
    }
}

@Composable
private fun Unlock(host: Host) {
    var pw by remember { mutableStateOf("") }
    val (busy, err, go) = rememberJob()
    Front("Unlock", busy, err) {
        Field(pw, { pw = it }, "Password", secret = true)
        if (host.needsKey) Text("Then hold your YubiKey to the phone", style = MaterialTheme.typography.bodySmall, color = muted)
        Primary("Unlock", enabled = !busy) { go { host.unlock(pw); pw = "" } }
    }
}

/** A screen under the list: back, its name, what it does. */
@Composable
private fun Page(title: String, nav: Nav, action: String = "", act: () -> Unit = {}, body: @Composable () -> Unit) = Column(Modifier.fillMaxSize()) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        TextButton({ nav.back() }) { Text("←  Back") }
        Text(title, Modifier.weight(1f), style = MaterialTheme.typography.titleLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
        if (action.isNotEmpty()) TextButton(act) { Text(action) }
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) { body() }
}

@Composable
private fun Store(host: Host, nav: Nav) {
    val said = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var tick by remember { mutableIntStateOf(0) }
    var generator by remember { mutableStateOf(false) }
    val say: (String) -> Unit = { m -> if (m.isNotBlank()) scope.launch { said.currentSnackbarData?.dismiss(); said.showSnackbar(m) } }
    val go: (suspend () -> String) -> Unit = { f ->
        scope.launch {
            say(runCatching { f() }.getOrElse { it.message?.removePrefix("Rust error: ") ?: "It failed" })
            tick++
        }
    }
    val copy: (String, String) -> Unit = { what, v -> host.copy(v); say("$what copied, cleared in 45 s") }
    Scaffold(
        snackbarHost = { SnackbarHost(said) },
        containerColor = MaterialTheme.colorScheme.background,
        floatingActionButton = {
            if (nav.screen == Screen.List) ExtendedFloatingActionButton({ nav.screen = Screen.Edit("") }) {
                Text("+  New", fontWeight = FontWeight.SemiBold)
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad)) {
            when (val s = nav.screen) {
                Screen.List -> Entries(host, nav, tick, go) { generator = true }
                is Screen.Entry -> Entry(host, nav, s.name, tick, copy, go)
                is Screen.Edit -> Edit(host, nav, s.name, go)
                is Screen.History -> History(host, nav, s.name, copy, go)
                Screen.Devices -> Devices(host, nav, tick, go)
                Screen.Settings -> Settings(host, nav)
            }
        }
    }
    if (generator) Generator(host, nav, copy) { generator = false }
}

@Composable
private fun Entries(host: Host, nav: Nav, tick: Int, go: (suspend () -> String) -> Unit, generator: () -> Unit) {
    var q by remember { mutableStateOf("") }
    var menu by remember { mutableStateOf(false) }
    val names by produceState(listOf<String>(), tick) { value = host.names() }
    val shown = names.filter { n -> q.split(' ').all { n.contains(it, ignoreCase = true) } }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.padding(start = 16.dp, end = 4.dp, top = 10.dp, bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                q, { q = it }, placeholder = { Text("Search") }, singleLine = true,
                shape = RoundedCornerShape(28.dp), modifier = Modifier.weight(1f),
            )
            Box {
                TextButton({ menu = true }) { Text("⋮", fontSize = 22.sp) }
                DropdownMenu(menu, { menu = false }) {
                    val item = @Composable { t: String, f: () -> Unit -> DropdownMenuItem({ Text(t) }, { menu = false; f() }) }
                    if (host.sync) item("Sync now") { go { host.syncNow() } }
                    item("Devices and sync") { nav.screen = Screen.Devices }
                    item("Password generator", generator)
                    item("Settings") { nav.screen = Screen.Settings }
                    item("Lock") { host.lock() }
                }
            }
        }
        if (shown.isEmpty()) Text(
            if (names.isEmpty()) "No entries yet. New adds the first." else "Nothing matches.",
            Modifier.fillMaxWidth().padding(32.dp), color = muted,
        )
        LazyColumn(contentPadding = PaddingValues(bottom = 88.dp)) {
            for ((group, of) in shown.groupBy { it.substringBeforeLast('/', "") }) {
                if (group.isNotEmpty()) item(key = "/$group") {
                    Text(
                        group.uppercase(), Modifier.padding(start = 20.dp, top = 16.dp, bottom = 4.dp),
                        style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary, letterSpacing = 1.sp,
                    )
                }
                for (n in of) item(key = n) {
                    val user by produceState("", n, tick) { value = runCatching { host.form(host.get(n)).user }.getOrDefault("") }
                    Column(Modifier.fillMaxWidth().clickable { nav.screen = Screen.Entry(n) }.padding(horizontal = 20.dp, vertical = 10.dp)) {
                        Text(n.substringAfterLast('/'), style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        if (user.isNotEmpty()) Text(user, style = MaterialTheme.typography.bodyMedium, color = muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
            }
        }
    }
}

/** One field of an entry: what it is, its value, its copy. */
@Composable
private fun Shown(label: String, value: String, mono: Boolean = false, act: String = "Copy", more: @Composable () -> Unit = {}, copy: (() -> Unit)? = null) =
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Label(label)
            Text(value, style = MaterialTheme.typography.bodyLarge, fontFamily = if (mono) FontFamily.Monospace else null)
        }
        more()
        if (copy != null) TextButton(copy) { Text(act) }
    }

@Composable
private fun Entry(host: Host, nav: Nav, name: String, tick: Int, copy: (String, String) -> Unit, go: (suspend () -> String) -> Unit) {
    val body by produceState("", name, tick) { value = runCatching { host.get(name) }.getOrDefault("") }
    val f = host.form(body)
    var shown by remember { mutableStateOf(false) }
    var sure by remember { mutableStateOf(false) }
    val now by produceState(System.currentTimeMillis() / 1000) { while (true) { delay(1000); value = System.currentTimeMillis() / 1000 } }
    Page(name, nav, "Edit", { nav.screen = Screen.Edit(name) }) {
        if (f.user.isNotEmpty()) Shown("Username", f.user) { copy("Username", f.user) }
        Shown(
            "Password", if (shown) f.pass else "•".repeat(f.pass.length.coerceAtMost(20)), mono = true,
            more = { TextButton({ shown = !shown }) { Text(if (shown) "Hide" else "Show") } },
        ) { copy("Password", f.pass) }
        val code = remember(body, now / 30) { host.code(body) }
        if (code.isNotEmpty()) Shown(
            "One-time code", code.chunked((code.length + 1) / 2).joinToString(" "), mono = true,
            more = { Text("${30 - now % 30} s", Modifier.padding(end = 4.dp), style = MaterialTheme.typography.bodySmall, color = muted) },
        ) { copy("Code", code) }
        if (f.url.isNotEmpty()) Shown("URL", f.url) { copy("URL", f.url) }
        if (f.notes.isNotEmpty()) Shown("Notes", f.notes)
        val files by produceState(listOf<String>(), name, tick) { value = runCatching { host.files(name) }.getOrDefault(listOf()) }
        for (file in files) Shown(
            "File", file, act = "Save",
            more = { TextButton({ go { host.put("$name/.files/$file", ""); "$file: removed" } }) { Text("Remove") } },
        ) { host.save(name, file) { m -> go { m } } }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton({ host.attach(name) { m -> go { m } } }) { Text("Attach a file") }
            OutlinedButton({ nav.screen = Screen.History(name) }) { Text("History") }
        }
        TextButton({ sure = true }) { Text("Delete this entry", color = MaterialTheme.colorScheme.error) }
    }
    if (sure) AlertDialog(
        { sure = false }, title = { Text("Delete $name?") },
        text = { Text("Its earlier versions stay in the store's history.") },
        confirmButton = { TextButton({ sure = false; go { host.remove(name); nav.screen = Screen.List; "$name: deleted" } }) { Text("Delete", color = MaterialTheme.colorScheme.error) } },
        dismissButton = { TextButton({ sure = false }) { Text("Cancel") } },
    )
}

@Composable
private fun Edit(host: Host, nav: Nav, old: String, go: (suspend () -> String) -> Unit) {
    var name by remember { mutableStateOf(old) }
    var f by remember { mutableStateOf(if (old.isEmpty()) Form(pass = host.generate(nav.gen)) else Form()) }
    var show by remember { mutableStateOf(old.isEmpty()) }
    LaunchedEffect(old) { if (old.isNotEmpty()) f = host.form(host.get(old)) }
    Page(if (old.isEmpty()) "New entry" else "Edit entry", nav) {
        Field(name, { name = it }, "Title (a / makes a group: mail/work)")
        Field(f.user, { f = f.copy(user = it) }, "Username")
        Field(f.pass, { f = f.copy(pass = it) }, "Password", secret = !show) {
            TextButton({ show = !show }) { Text(if (show) "Hide" else "Show") }
        }
        OutlinedButton({ f = f.copy(pass = host.generate(nav.gen)); show = true }) { Text("Generate a password") }
        Field(f.url, { f = f.copy(url = it) }, "URL")
        Field(f.otp, { f = f.copy(otp = it) }, "One-time code: its otpauth:// address")
        Field(f.notes, { f = f.copy(notes = it) }, "Notes", lines = 3)
        Primary("Save", enabled = name.isNotBlank() && !name.endsWith("/")) {
            val (to, text) = name.trim() to host.text(f)
            go {
                if (old.isNotEmpty() && old != to) host.rename(old, to)
                host.put(to, text)
                nav.screen = Screen.Entry(to)
                "$to: saved"
            }
        }
    }
}

/** One of two ways, the chosen one filled. */
@Composable
private fun Way(text: String, on: Boolean, pick: () -> Unit) =
    if (on) Button(pick, shape = RoundedCornerShape(10.dp)) { Text(text) }
    else OutlinedButton(pick, shape = RoundedCornerShape(10.dp)) { Text(text) }

@Composable
private fun Tick(text: String, on: Boolean, set: (Boolean) -> Unit) =
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { set(!on) }) {
        Checkbox(on, set)
        Text(text)
    }

@Composable
private fun Generator(host: Host, nav: Nav, copy: (String, String) -> Unit, close: () -> Unit) {
    val g = nav.gen
    var n by remember { mutableIntStateOf(0) }
    val pw = remember(g, n) { host.generate(g) }
    AlertDialog(
        close, title = { Text("Password generator") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    pw, Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.background, RoundedCornerShape(10.dp)).padding(12.dp),
                    fontFamily = mono,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Way("Characters", !g.words) { nav.gen = g.copy(words = false) }
                    Way("Speakable", g.words) { nav.gen = g.copy(words = true) }
                }
                if (g.words) {
                    Label("${g.count} words  \u00B7  ${g.bits} bits")
                    Slider(g.count.toFloat(), { nav.gen = g.copy(count = it.toInt()) }, valueRange = 3f..8f, steps = 4)
                    Row {
                        Tick("with-dashes", g.hyphens) { nav.gen = g.copy(hyphens = it) }
                        Tick("1337", g.leet) { nav.gen = g.copy(leet = it) }
                    }
                } else {
                    Label("${g.len} characters  \u00B7  ${g.bits} bits")
                    Slider(g.len.toFloat(), { nav.gen = g.copy(len = it.toInt()) }, valueRange = 8f..64f)
                    Tick("Symbols", g.symbols) { nav.gen = g.copy(symbols = it) }
                }
                Text("New entries start with a password made this way.", style = MaterialTheme.typography.bodySmall, color = muted)
            }
        },
        confirmButton = { TextButton({ copy("Generated password", pw) }) { Text("Copy") } },
        dismissButton = {
            Row {
                TextButton({ n++ }) { Text("Another") }
                TextButton(close) { Text("Close") }
            }
        },
    )
}

/** What an entry was, version by version, and a way back. */
@Composable
private fun History(host: Host, nav: Nav, name: String, copy: (String, String) -> Unit, go: (suspend () -> String) -> Unit) {
    val all by produceState(listOf<Pair<Long, String>>(), name) { value = runCatching { host.history(name) }.getOrDefault(listOf()) }
    val date = remember { java.text.SimpleDateFormat("yyyy-MM-dd  HH:mm") }
    Page("History", nav) {
        Text(name, color = muted)
        all.forEachIndexed { i, (ms, body) ->
            val f = host.form(body)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(date.format(java.util.Date(ms)), style = MaterialTheme.typography.bodyLarge)
                    Label(if (body.isEmpty()) "deleted" else if (i == 0) "now" else f.user)
                }
                if (body.isNotEmpty()) TextButton({ copy("That version's password", f.pass) }) { Text("Copy") }
                if (body.isNotEmpty() && i > 0) TextButton({ go { host.put(name, body); nav.screen = Screen.Entry(name); "$name: restored" } }) { Text("Restore") }
            }
        }
        Text("Nothing is ever overwritten: each change is a new version.", style = MaterialTheme.typography.bodySmall, color = muted)
    }
}

@Composable
private fun Devices(host: Host, nav: Nav, tick: Int, go: (suspend () -> String) -> Unit) {
    var on by remember { mutableStateOf(host.sync) }
    val peers by produceState(listOf<String>(), tick) { value = host.peers() }
    var name by remember { mutableStateOf("") }
    var pairing by remember { mutableStateOf<Triple<String, String, String>?>(null) }
    Page("Devices and sync", nav) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f).padding(end = 12.dp)) {
                Text("Sync with my devices", style = MaterialTheme.typography.bodyLarge)
                Text(
                    "Devices that hold this store sync with each other directly, sealed end to end. No account, no server keeps a copy. Off: the app never uses the network.",
                    style = MaterialTheme.typography.bodySmall, color = muted,
                )
            }
            Switch(on, { on = it; host.sync = it })
        }
        if (on && peers.isNotEmpty()) OutlinedButton({ go { host.syncNow() } }) { Text("Sync now") }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Label("PAIRED DEVICES")
        if (peers.isEmpty()) Text("No other device yet.", color = muted)
        for (p in peers) Row(verticalAlignment = Alignment.CenterVertically) {
            Text(p, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
            TextButton({ go { host.forget(p); "$p: forgotten" } }) { Text("Forget") }
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Label("ADD A DEVICE")
        Field(name, { name = it }, "A name for it")
        OutlinedButton({
            val n = name.trim()
            go { host.pair(n).let { pairing = Triple(n, it.first, it.second) }; host.sync = true; on = true; "" }
        }, enabled = name.isNotBlank()) { Text("Show a pairing code") }
        pairing?.let { (who, code, pw) ->
            Column(
                Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface, RoundedCornerShape(12.dp)).padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text("On $who: Join a store, then type", style = MaterialTheme.typography.bodySmall, color = muted)
                Label("Code")
                Text(code, fontFamily = mono, fontSize = 20.sp)
                Label("Password")
                Text(pw, fontFamily = mono, fontSize = 20.sp)
            }
        }
    }
}

@Composable
private fun Settings(host: Host, nav: Nav) = Page("Settings", nav) {
    for ((what, how) in listOf(
        "Locking" to "The store locks whenever the app leaves the screen.",
        "Clipboard" to "Copied secrets are marked sensitive and leave the clipboard after 45 s.",
        "Screen" to "Screenshots and overlays are blocked while the app shows.",
        "Backups" to "The store is kept out of Android's backups and device transfers: pair a device instead.",
    )) Column {
        Text(what, style = MaterialTheme.typography.bodyLarge)
        Text(how, style = MaterialTheme.typography.bodySmall, color = muted)
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    Text("apasa ${host.version}  ·  GPL-3.0-or-later", style = MaterialTheme.typography.bodySmall, color = muted)
}
