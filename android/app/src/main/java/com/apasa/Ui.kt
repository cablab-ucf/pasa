package com.apasa

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
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
import androidx.compose.material3.RadioButton
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
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
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
    val otp: String = "", val notes: String = "", val tags: String = "",
    /** A date, YYYY-MM-DD; and every other `name: value` line. */
    val expires: String = "", val more: String = "",
)

/** Entries with a weak password and its bits; those sharing one; those past their date. */
data class Health(
    val weak: List<Pair<String, Int>> = listOf(), val reused: List<List<String>> = listOf(),
    val expired: List<String> = listOf(),
)

/** A hardware key's part: none; a tap (and PIN) that opens the store beside the password; or needed with the password. */
enum class Key { None, Quick, Both }

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
    /** Quick unlock here: null if off, else whether a PIN goes with the tap. */
    val quick: Boolean?
    /** The phone has NFC and it is switched off: a key can then only be plugged in. */
    val nfcOff: Boolean
    /** Open the phone's NFC settings. */
    fun nfcSettings()
    suspend fun create(pw: String, key: Key, pin: String)
    suspend fun unlock(pw: String)
    suspend fun unlockQuick(pin: String)
    /** Quick unlock on with [pin] (empty: none), or off (null). */
    suspend fun setQuick(pin: String?)
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
    /** A guess at a typed password's bits. */
    fun strength(pw: String): Int
    /** When [name] was made and last changed (ms). */
    suspend fun times(name: String): Pair<Long, Long>?
    suspend fun health(): Health
    /** The store in numbers: what each counts, and the count. */
    suspend fun stats(): List<Pair<String, String>>
    /** How often known breaches hold [pw]: asks haveibeenpwned.com. */
    suspend fun pwned(pw: String): Long
    fun open(url: String)
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
    data object Health : Screen
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

/** Something being done: whether it still is, what went wrong, how to start it, how to stop it. */
private data class Work(val busy: Boolean, val err: String, val go: (suspend () -> Unit) -> Unit, val stop: () -> Unit)

/** Runs what [Work.go] is given, busy meanwhile; what went wrong, in the app's words. */
@Composable
private fun rememberJob(): Work {
    var busy by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf("") }
    var running by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    val scope = rememberCoroutineScope()
    return Work(busy, err, { f ->
        running = scope.launch {
            busy = true
            err = try {
                f()
                ""
            } catch (e: kotlinx.coroutines.CancellationException) {
                ""
            } catch (e: Throwable) {
                e.message?.removePrefix("Rust error: ") ?: "It failed"
            }
            busy = false
        }
    }) {
        running?.cancel()
        busy = false
    }
}

@Composable
private fun Label(t: String) = Text(t, style = MaterialTheme.typography.labelMedium, color = muted)

/** An eye, struck through while what it watches is hidden. */
@Composable
private fun Eye(open: Boolean, tint: Color) = Canvas(Modifier.size(22.dp)) {
    val (w, h) = size.width to size.height
    drawOval(tint, Offset(w * 0.06f, h * 0.26f), Size(w * 0.88f, h * 0.48f), style = Stroke(w * 0.09f))
    drawCircle(tint, w * 0.13f, center)
    if (!open) drawLine(tint, Offset(w * 0.15f, h * 0.85f), Offset(w * 0.85f, h * 0.15f), w * 0.09f)
}

/**
 * A field. [secret]: hidden, with an eye to show it ([shown]). [error]: what is wrong with it, said under it.
 * [prose]: text to spell-check and capitalise, as notes are; everything else is typed as it is.
 * [done]: what the keyboard's Done does.
 */
@Composable
private fun Field(
    v: String, set: (String) -> Unit, label: String, secret: Boolean = false, lines: Int = 1,
    error: String = "", prose: Boolean = false, done: (() -> Unit)? = null,
    shown: MutableState<Boolean> = remember { mutableStateOf(false) },
    trailing: (@Composable () -> Unit)? = null,
) = OutlinedTextField(
    v, set, label = { Text(label) }, singleLine = lines == 1, minLines = lines,
    isError = error.isNotEmpty(),
    supportingText = if (error.isEmpty()) null else ({ Text(error) }),
    visualTransformation = if (secret && !shown.value) PasswordVisualTransformation() else VisualTransformation.None,
    keyboardOptions = KeyboardOptions(
        capitalization = if (prose) KeyboardCapitalization.Sentences else KeyboardCapitalization.None,
        autoCorrectEnabled = prose,
        keyboardType = if (secret) KeyboardType.Password else KeyboardType.Text,
        imeAction = if (done != null) ImeAction.Done else ImeAction.Default,
    ),
    keyboardActions = KeyboardActions(onDone = { done?.invoke() }),
    trailingIcon = trailing ?: if (!secret) null else ({
        Box(
            Modifier.size(44.dp).clickable { shown.value = !shown.value }
                .semantics { contentDescription = if (shown.value) "Hide" else "Show" },
            contentAlignment = Alignment.Center,
        ) { Eye(shown.value, muted) }
    }),
    shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth(),
)

@Composable
private fun Primary(text: String, enabled: Boolean = true, go: () -> Unit) =
    Button(go, enabled = enabled, shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth().height(48.dp)) {
        Text(text, fontWeight = FontWeight.SemiBold)
    }

/** What so many bits are called, and their colour: under 40 poor, under 65 weak, under 100 good. */
private fun grade(bits: Int) = when {
    bits < 40 -> "Poor" to Color(0xFFE5604F)
    bits < 65 -> "Weak" to Color(0xFFE0A040)
    bits < 100 -> "Good" to Color(0xFF9CC25A)
    else -> "Excellent" to Color(0xFF4FB286)
}

/**
 * A bar that fills and turns from red to green as a password's bits grow. With a [goal] (the store's own
 * password: 256) the bar is full there, and says how far it is: a suggestion, nothing is refused.
 */
@Composable
private fun Meter(bits: Int, goal: Int = 0) = Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
    val (name, colour) = grade(bits)
    val full = if (goal > 0) goal else 128
    Box(Modifier.fillMaxWidth().height(6.dp).background(MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(3.dp))) {
        Box(Modifier.fillMaxWidth((bits.toFloat() / full).coerceIn(0f, 1f)).height(6.dp).background(colour, RoundedCornerShape(3.dp)))
    }
    val said = when {
        goal == 0 -> "$name: about $bits bits"
        bits >= goal -> "About $bits bits: the $goal suggested, and more"
        else -> "About $bits bits of the $goal suggested"
    }
    Text(said, style = MaterialTheme.typography.bodySmall, color = colour)
}

/**
 * The name, one card in the middle for what the app wants first, and the other way in, small, in the corner.
 * While [work] is busy the card says [wait] and offers to stop.
 */
@Composable
private fun Front(
    title: String, work: Work, ask: String = "", link: String = "", other: () -> Unit = {},
    wait: String = "", host: Host? = null, body: @Composable () -> Unit,
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
            Doing(work, wait, host)
        }
        Spacer(Modifier.height(64.dp))
    }
    if (link.isNotEmpty()) Row(Modifier.align(Alignment.BottomEnd), verticalAlignment = Alignment.CenterVertically) {
        Text(ask, style = MaterialTheme.typography.bodySmall, color = muted)
        TextButton(other, contentPadding = PaddingValues(horizontal = 8.dp)) { Text(link) }
    }
}

/** Under what was asked for: that it is being done, with a way to stop; or why it failed. */
@Composable
private fun Doing(work: Work, wait: String = "", host: Host? = null) {
    if (work.busy) {
        if (wait.isNotEmpty()) Text(wait, color = MaterialTheme.colorScheme.primary)
        Row(verticalAlignment = Alignment.CenterVertically) {
            LinearProgressIndicator(Modifier.weight(1f))
            TextButton(work.stop) { Text("Cancel") }
        }
    }
    if (work.err.isNotEmpty()) Text(work.err, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
    // What is wrong, and where to put it right.
    if (host != null && host.nfcOff && work.err.contains("NFC")) OutlinedButton(host::nfcSettings) { Text("Open NFC settings") }
}

/** Before a key is asked for: that NFC is off, and where to turn it on. */
@Composable
private fun NfcOff(host: Host) {
    if (!host.nfcOff) return
    Text("NFC is off: turn it on to tap the YubiKey, or plug the key in.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    OutlinedButton(host::nfcSettings) { Text("Open NFC settings") }
}

@Composable
private fun Create(host: Host, nav: Nav) {
    var pw by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    var key by remember { mutableStateOf(Key.None) }
    var pin by remember { mutableStateOf("") }
    val shown = remember { mutableStateOf(false) }
    // A generated password and its bits: known, where a typed one's are guessed.
    var made by remember { mutableStateOf("" to 0) }
    val work = rememberJob()
    val ok = pw.isNotEmpty() && pw == again && !work.busy
    val create = { if (ok) work.go { host.create(pw, key, pin) } }
    Front(
        "Create your store", work, "A store on another device already?", "Join it", { nav.joining = true },
        wait = if (key != Key.None) "Hold your YubiKey to the phone, or plug it in" else "", host = host,
    ) {
        Text(
            "Its password opens everything, and is the way back in when all else is lost: a long one. 256 bits is the suggestion.",
            style = MaterialTheme.typography.bodySmall, color = muted,
        )
        Field(pw, { pw = it }, "Password", secret = true, shown = shown)
        if (pw.isNotEmpty()) Meter(if (pw == made.first) made.second else host.strength(pw), goal = 256)
        OutlinedButton({
            val g = Gen(words = true, count = 12, hyphens = true)
            made = host.generate(g) to g.bits
            pw = made.first
            again = made.first
            shown.value = true
        }) { Text("Generate one and show it") }
        if (pw.isNotEmpty() && pw == made.first) {
            // In full, as the field cuts it off: four words a line.
            Text(
                pw.split('-').chunked(4).joinToString("-\n") { it.joinToString("-") },
                Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.background, RoundedCornerShape(10.dp)).padding(12.dp),
                fontFamily = mono, fontSize = 13.sp,
            )
            Text(
                "Twelve made-up words, ${made.second} bits. Write it down and keep it somewhere safe before going on.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary,
            )
        }
        Field(
            again, { again = it }, "Password, again", secret = true, shown = shown,
            error = if (again.isNotEmpty() && pw != again) "The passwords differ" else "", done = create,
        )
        Row(Modifier.fillMaxWidth().clickable { key = if (key == Key.None) Key.Quick else Key.None }, verticalAlignment = Alignment.CenterVertically) {
            Checkbox(key != Key.None, { key = if (it) Key.Quick else Key.None })
            Text("Use a hardware key (YubiKey)")
        }
        if (key != Key.None) {
            Choice("To unlock quickly", "A tap and a PIN open the store. The password still opens it alone if the key is lost.", key == Key.Quick) { key = Key.Quick }
            if (key == Key.Quick) Field(pin, { pin = it }, "PIN (empty: none)", secret = true, done = create)
            Choice("As a second factor", "Needed together with the password, every time.", key == Key.Both) { key = Key.Both }
            NfcOff(host)
        }
        Primary("Create store", enabled = ok, go = create)
    }
}

@Composable
private fun Join(host: Host, nav: Nav) {
    var name by remember { mutableStateOf("home") }
    var code by remember { mutableStateOf("") }
    var pw by remember { mutableStateOf("") }
    val work = rememberJob()
    val ok = name.isNotBlank() && code.isNotBlank() && !work.busy
    val join = { if (ok) work.go { host.join(name.trim(), code.trim(), pw) } }
    Front("Join a store", work, "No store yet?", "Create one", { nav.joining = false }, wait = "Reaching the other device") {
        Text(
            "On the device that has it: Devices, Add a device (or pasa pair NAME). It shows a code and a password.",
            style = MaterialTheme.typography.bodySmall, color = muted,
        )
        Field(name, { name = it }, "A name for that device", error = if (name.isBlank()) "It needs a name" else "")
        Field(code, { code = it }, "Code") { TextButton({ host.scan { code = it } }) { Text("Scan") } }
        Field(pw, { pw = it }, "Pairing password", secret = true, done = join)
        Primary("Join", enabled = ok, go = join)
    }
}

/** One of a few ways, with what it means. */
@Composable
private fun Choice(title: String, about: String, on: Boolean, pick: () -> Unit) =
    Row(Modifier.fillMaxWidth().clickable(onClick = pick), verticalAlignment = Alignment.CenterVertically) {
        RadioButton(on, pick)
        Column {
            Text(title)
            Text(about, style = MaterialTheme.typography.bodySmall, color = muted)
        }
    }

@Composable
private fun Unlock(host: Host) {
    var pw by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var byPassword by remember { mutableStateOf(false) }
    val work = rememberJob()
    val quick = host.quick
    val tap = "Hold your YubiKey to the phone, or plug it in"
    if (quick != null && !byPassword) {
        val open = { if (!work.busy) work.go { host.unlockQuick(pin); pin = "" } }
        return Front("Unlock", work, "No key at hand?", "Use the password", { work.stop(); byPassword = true }, wait = tap, host = host) {
            if (quick) Field(pin, { pin = it }, "PIN", secret = true, done = open)
            NfcOff(host)
            Primary("Unlock with the YubiKey", enabled = !work.busy, go = open)
        }
    }
    val open = { if (!work.busy) work.go { host.unlock(pw); pw = "" } }
    Front(
        "Unlock", work, if (quick != null) "Quick unlock is on." else "", if (quick != null) "Use the YubiKey" else "",
        { work.stop(); byPassword = false }, wait = if (host.needsKey) tap else "", host = host,
    ) {
        Field(pw, { pw = it }, "Password", secret = true, done = open)
        if (host.needsKey) NfcOff(host)
        Primary("Unlock", enabled = !work.busy, go = open)
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
                Screen.List -> Entries(host, nav, tick, copy, go) { generator = true }
                is Screen.Entry -> Entry(host, nav, s.name, tick, copy, go)
                is Screen.Edit -> Edit(host, nav, s.name, go)
                is Screen.History -> History(host, nav, s.name, copy, go)
                Screen.Devices -> Devices(host, nav, tick, go)
                Screen.Health -> Health(host, nav)
                Screen.Settings -> Settings(host, nav)
            }
        }
    }
    if (generator) Generator(host, nav, copy) { generator = false }
}

@Composable
private fun Entries(host: Host, nav: Nav, tick: Int, copy: (String, String) -> Unit, go: (suspend () -> String) -> Unit, generator: () -> Unit) {
    var q by remember { mutableStateOf("") }
    var menu by remember { mutableStateOf(false) }
    val names by produceState(listOf<String>(), tick) { value = host.names() }
    var tag by remember { mutableStateOf("") }
    val forms by produceState(mapOf<String, Form>(), names, tick) {
        value = names.associateWith { runCatching { host.form(host.get(it)) }.getOrDefault(Form()) }
    }
    val tagsOf = { n: String -> forms[n]?.tags.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() } }
    val tags = names.flatMap(tagsOf).distinct().sorted()
    val shown = names.filter { n ->
        val f = forms[n] ?: Form()
        val hay = "$n ${f.user} ${f.url} ${f.tags} ${f.notes}"
        (tag.isEmpty() || tag in tagsOf(n)) && q.split(' ').all { hay.contains(it, ignoreCase = true) }
    }
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
                    item("Password health") { nav.screen = Screen.Health }
                    item("Settings") { nav.screen = Screen.Settings }
                    item("Lock") { host.lock() }
                }
            }
        }
        if (tags.isNotEmpty()) Row(
            Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            for (t in tags) Text(
                t, Modifier.background(
                    if (t == tag) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surface, RoundedCornerShape(16.dp),
                ).border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(16.dp))
                    .clickable { tag = if (t == tag) "" else t }.padding(horizontal = 12.dp, vertical = 6.dp),
                style = MaterialTheme.typography.labelLarge,
                color = if (t == tag) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface,
            )
        }
        Text(
            if (shown.size == names.size) "${names.size} entries" else "${shown.size} of ${names.size} entries",
            Modifier.padding(start = 20.dp, top = 6.dp), style = MaterialTheme.typography.labelMedium, color = muted,
        )
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
                    val f = forms[n] ?: Form()
                    var held by remember { mutableStateOf(false) }
                    Row(
                        Modifier.fillMaxWidth().combinedClickable(onLongClick = { held = true }) { nav.screen = Screen.Entry(n) }
                            .padding(horizontal = 20.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(n.substringAfterLast('/'), style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            val under = listOf(f.user, f.url.substringAfter("://")).filter { it.isNotEmpty() }.joinToString("  \u00B7  ")
                            if (under.isNotEmpty()) Text(under, style = MaterialTheme.typography.bodyMedium, color = muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        // The password's grade, as a dot.
                        if (f.pass.isNotEmpty()) Box(Modifier.padding(start = 12.dp).size(10.dp).background(grade(host.strength(f.pass)).second, RoundedCornerShape(5.dp)))
                        // What can be done with an entry, under a long press.
                        DropdownMenu(held, { held = false }) {
                            val item = @Composable { t: String, act: () -> Unit -> DropdownMenuItem({ Text(t) }, { held = false; act() }) }
                            if (f.user.isNotEmpty()) item("Copy username") { copy("Username", f.user) }
                            item("Copy password") { copy("Password", f.pass) }
                            host.code(host.text(f)).let { c -> if (c.isNotEmpty()) item("Copy one-time code") { copy("Code", c) } }
                            if (f.url.isNotEmpty()) item("Copy URL") { copy("URL", f.url) }
                            if (f.url.startsWith("http")) item("Open URL") { host.open(f.url) }
                            item("Edit") { nav.screen = Screen.Edit(n) }
                            item("History") { nav.screen = Screen.History(n) }
                        }
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
        if (f.url.isNotEmpty()) Shown(
            "URL", f.url,
            more = { if (f.url.startsWith("http")) TextButton({ host.open(f.url) }) { Text("Open") } },
        ) { copy("URL", f.url) }
        if (f.tags.isNotEmpty()) Shown("Tags", f.tags)
        if (f.expires.isNotEmpty()) Shown("Expires", f.expires)
        for (line in f.more.lines().filter { ':' in it }) {
            val value = line.substringAfter(':').trim()
            Shown(line.substringBefore(':'), value) { copy(line.substringBefore(':'), value) }
        }
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
        val times by produceState<Pair<Long, Long>?>(null, name, tick) { value = runCatching { host.times(name) }.getOrNull() }
        times?.let { (made, changed) ->
            val date = remember { java.text.SimpleDateFormat("yyyy-MM-dd HH:mm") }
            Text(
                "Changed ${date.format(java.util.Date(changed))}   \u00B7   Made ${date.format(java.util.Date(made))}",
                style = MaterialTheme.typography.bodySmall, color = muted,
            )
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
    val show = remember { mutableStateOf(old.isEmpty()) }
    LaunchedEffect(old) { if (old.isNotEmpty()) f = host.form(host.get(old)) }
    var advanced by remember { mutableStateOf(false) }
    // The user names most entries have, to pick from.
    val users by produceState(listOf<String>()) {
        value = host.names().mapNotNull { n -> runCatching { host.form(host.get(n)).user }.getOrNull()?.takeIf { it.isNotEmpty() } }
            .groupingBy { it }.eachCount().entries.sortedByDescending { it.value }.map { it.key }.take(5)
    }
    Page(if (old.isEmpty()) "New entry" else "Edit entry", nav) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Way("Entry", !advanced) { advanced = false }
            Way("Advanced", advanced) { advanced = true }
        }
        if (advanced) {
            val dated = f.expires.isEmpty() || Regex("\\d{4}-\\d{2}-\\d{2}").matches(f.expires)
            Field(f.expires, { f = f.copy(expires = it) }, "Expires (YYYY-MM-DD; empty: never)", error = if (dated) "" else "A date as 2027-01-31")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val day = { days: Long -> java.text.SimpleDateFormat("yyyy-MM-dd").format(java.util.Date(System.currentTimeMillis() + days * 86_400_000)) }
                OutlinedButton({ f = f.copy(expires = day(90)) }) { Text("In 90 days") }
                OutlinedButton({ f = f.copy(expires = day(365)) }) { Text("In a year") }
                TextButton({ f = f.copy(expires = "") }) { Text("Never") }
            }
            Field(f.more, { f = f.copy(more = it) }, "Other fields: one a line, as  name: value", lines = 5)
            Text("Files are attached and removed on the entry's own screen.", style = MaterialTheme.typography.bodySmall, color = muted)
        } else {
            Field(
                name, { name = it }, "Title (a / makes a group: mail/work)",
                error = if (name.isBlank()) "It needs a title" else if (name.endsWith("/")) "A name goes after the /" else "",
            )
            Field(f.user, { f = f.copy(user = it) }, "Username")
            val picks = users.filter { it != f.user && it.startsWith(f.user) }.take(4)
            if (picks.isNotEmpty()) Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                for (u in picks) Text(
                    u, Modifier.background(MaterialTheme.colorScheme.surface, RoundedCornerShape(16.dp))
                        .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(16.dp))
                        .clickable { f = f.copy(user = u) }.padding(horizontal = 12.dp, vertical = 6.dp),
                    style = MaterialTheme.typography.labelLarge,
                )
            }
            Field(f.pass, { f = f.copy(pass = it) }, "Password", secret = true, shown = show)
            Meter(host.strength(f.pass))
            OutlinedButton({ f = f.copy(pass = host.generate(nav.gen)); show.value = true }) { Text("Generate a password") }
            Field(f.url, { f = f.copy(url = it) }, "URL")
            Field(f.tags, { f = f.copy(tags = it) }, "Tags (commas between)")
            Field(f.otp, { f = f.copy(otp = it) }, "One-time code: its otpauth:// address")
            Field(f.notes, { f = f.copy(notes = it) }, "Notes", lines = 3, prose = true)
        }
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

/** Weak, shared and, if asked, breached passwords. */
@Composable
private fun Health(host: Host, nav: Nav) {
    val found by produceState<Health?>(null) { value = runCatching { host.health() }.getOrNull() }
    val stats by produceState(listOf<Pair<String, String>>()) { value = runCatching { host.stats() }.getOrDefault(listOf()) }
    var numbers by remember { mutableStateOf(false) }
    var breached by remember { mutableStateOf<List<Pair<String, Long>>?>(null) }
    val work = rememberJob()
    val (busy, _, go) = work
    Page("Password health", nav) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Way("Health", !numbers) { numbers = false }
            Way("Statistics", numbers) { numbers = true }
        }
        if (numbers) {
            for ((what, n) in stats) Row {
                Text(what, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
                Text(n, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
            }
            return@Page
        }
        val (weak, reused, expired) = found ?: Health()
        Label("WEAK: ${weak.size}")
        for ((n, bits) in weak) Row(Modifier.fillMaxWidth().clickable { nav.screen = Screen.Entry(n) }, verticalAlignment = Alignment.CenterVertically) {
            Text(n, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
            Text("about $bits bits", style = MaterialTheme.typography.bodySmall, color = grade(bits).second)
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Label("SHARED BY SEVERAL ENTRIES: ${reused.size}")
        for (g in reused) Text(g.joinToString(",  "), style = MaterialTheme.typography.bodyLarge)
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Label("EXPIRED: ${expired.size}")
        for (n in expired) Text(n, Modifier.fillMaxWidth().clickable { nav.screen = Screen.Entry(n) }, style = MaterialTheme.typography.bodyLarge)
        breached?.let { hits ->
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Label("IN KNOWN BREACHES: ${hits.size}")
            for ((n, times) in hits) Row(Modifier.fillMaxWidth().clickable { nav.screen = Screen.Entry(n) }, verticalAlignment = Alignment.CenterVertically) {
                Text(n, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
                Text("seen $times times", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Text(
            "A breach check asks haveibeenpwned.com. Of each password only the first 5 hex digits of its SHA-1 leave the phone; the site cannot tell which password was meant.",
            style = MaterialTheme.typography.bodySmall, color = muted,
        )
        Doing(work, "Asking haveibeenpwned.com")
        OutlinedButton({
            go { breached = host.names().mapNotNull { n -> host.pwned(host.form(host.get(n)).pass).takeIf { it > 0 }?.let { n to it } } }
        }, enabled = !busy) { Text("Check for breaches online") }
    }
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
    var pin by remember { mutableStateOf("") }
    val work = rememberJob()
    val (busy, _, go) = work
    Text("Quick unlock", style = MaterialTheme.typography.bodyLarge)
    Text(
        "A tap of your YubiKey and a PIN open the store on this phone. The password still opens it alone: keep it long.",
        style = MaterialTheme.typography.bodySmall, color = muted,
    )
    when (val q = host.quick) {
        null -> {
            Field(pin, { pin = it }, "PIN (empty: none)", secret = true)
            OutlinedButton({ go { host.setQuick(pin); pin = "" } }, enabled = !busy) { Text("Turn on") }
        }
        else -> Row(verticalAlignment = Alignment.CenterVertically) {
            Text(if (q) "On, with a PIN" else "On, no PIN", Modifier.weight(1f))
            TextButton({ go { host.setQuick(null) } }) { Text("Turn off") }
        }
    }
    if (host.quick == null) NfcOff(host)
    Doing(work, "Hold your YubiKey to the phone, or plug it in", host)
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
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
