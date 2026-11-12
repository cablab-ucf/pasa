package com.apasa

import android.app.Activity
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.client.Ctap2Client
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider
import com.yubico.yubikit.fido.client.extensions.HmacSecretExtension
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions
import com.yubico.yubikit.fido.webauthn.SerializationType
import com.yubico.yubikit.yubiotp.YubiOtpSession
import java.security.SecureRandom
import java.util.Base64

// No network here or in Yubico's library: android/no-network.sh fails the build otherwise.
private const val RP = "pasa"

private fun rand(n: Int) = ByteArray(n).also { SecureRandom().nextBytes(it) }
private fun b64(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

private fun <T> onFido(d: YubiKeyDevice, use: (Ctap2Client) -> T, done: (Result<T>) -> Unit) {
    val run = { session: () -> Ctap2Session ->
        done(runCatching { use(Ctap2Client(session(), listOf(HmacSecretExtension(true)))) }.recoverCatching { throw told(it) })
    }
    if (d.supportsConnection(FidoConnection::class.java)) d.requestConnection(FidoConnection::class.java) { c -> run { Ctap2Session(c.value) } }
    else d.requestConnection(SmartCardConnection::class.java) { c -> run { Ctap2Session(c.value) } }
}

private suspend fun <T> withFido(a: Activity, use: (Ctap2Client) -> T): T = withDevice(a) { d, done -> onFido(d, use, done) }

/** CTAP errors in the user's words; an IOException passes on, for [said]. */
private fun told(e: Throwable): Throwable {
    val code = generateSequence(e) { it.cause }.filterIsInstance<CtapException>().firstOrNull()?.ctapError
    return when {
        e is Said || e is java.io.IOException -> e
        code == CtapException.ERR_PIN_INVALID -> Said("Wrong PIN for this security key.")
        code == CtapException.ERR_PIN_BLOCKED || code == CtapException.ERR_PIN_AUTH_BLOCKED ->
            Said("This security key's PIN is blocked after too many wrong tries: use the password.")
        code == CtapException.ERR_NO_CREDENTIALS -> Said("This security key is not one of this store's.")
        else -> Said("The security key refused: ${e.message ?: e.javaClass.simpleName}")
    }
}

internal fun creation(uv: Boolean) = PublicKeyCredentialCreationOptions.fromMap(
    mapOf(
        "rp" to mapOf("id" to RP, "name" to RP),
        "user" to mapOf("id" to b64(rand(16)), "name" to RP, "displayName" to RP),
        "challenge" to b64(rand(32)),
        "pubKeyCredParams" to listOf(mapOf("type" to "public-key", "alg" to -7)),
        // Non-resident: keys hold few resident credentials, and the store keeps the id.
        "authenticatorSelection" to mapOf("residentKey" to "discouraged", "userVerification" to if (uv) "required" else "discouraged"),
        "extensions" to mapOf("hmacCreateSecret" to true),
    ),
)

internal fun request(creds: List<ByteArray>, salt: ByteArray, uv: Boolean) = PublicKeyCredentialRequestOptions.fromMap(
    mapOf(
        "challenge" to b64(rand(32)), "rpId" to RP,
        "allowCredentials" to creds.map { mapOf("type" to "public-key", "id" to b64(it)) },
        "userVerification" to if (uv) "required" else "discouraged",
        "extensions" to mapOf("hmacGetSecret" to mapOf("salt1" to b64(salt))),
    ),
)

/** (credential, secret for [salt]); hmac-secret gives another secret with [uv] than without. */
private fun secret(c: Ctap2Client, creds: List<ByteArray>, salt: ByteArray, uv: Boolean, pin: CharArray?): Pair<ByteArray, ByteArray> {
    val got = c.getAssertion(ClientDataProvider.fromHash(rand(32)), request(creds, salt, uv), RP, if (uv) pin else null, null)
    val out = (got.clientExtensionResults?.toMap(SerializationType.JSON)?.get("hmacGetSecret") as? Map<*, *>)?.get("output1") as? String
        ?: throw Said("This key gave no secret: it does not do hmac-secret.")
    return got.rawId to Base64.getUrlDecoder().decode(out)
}

private fun pinOf(c: Ctap2Client, pin: String): CharArray? {
    if (!c.isPinConfigured) return null
    if (pin.isEmpty()) throw Said("This key has a PIN: type it, then tap the key again.")
    return pin.toCharArray()
}

/** (credential, PIN used, secret for [salt]) of a new credential. */
suspend fun fidoNew(a: Activity, salt: ByteArray, pin: String): Triple<ByteArray, Boolean, ByteArray> = withFido(a) { c ->
    val typed = pinOf(c, pin)
    val made = c.makeCredential(ClientDataProvider.fromHash(rand(32)), creation(typed != null), RP, typed, null, null)
    Triple(made.rawId, typed != null, secret(c, listOf(made.rawId), salt, typed != null, typed).second)
}

private fun ctapSecret(c: Ctap2Client, keys: List<Pair<ByteArray, Boolean>>, salt: ByteArray, pin: String): Pair<ByteArray, ByteArray> {
    val typed = if (keys.any { it.second }) pinOf(c, pin) else null
    val got = secret(c, keys.map { it.first }, salt, typed != null, typed)
    if (keys.first { it.first.contentEquals(got.first) }.second != (typed != null))
        throw Said("This key's PIN was set or removed since it was added: use the password, then add the key again.")
    return got
}

sealed interface Tapped {
    class Slot2(val answer: ByteArray) : Tapped
    class Ctap(val cred: ByteArray, val secret: ByteArray) : Tapped
}

/** One tap: slot 2 first (quick unlock, if on), else CTAP2 if it is one of [keys]. */
suspend fun anyKey(a: Activity, challenge: ByteArray?, salt: ByteArray?, keys: List<Pair<ByteArray, Boolean>>, pin: String): Tapped =
    withDevice(a) { d, done ->
        val ctap = { before: Throwable? ->
            if (salt == null || keys.isEmpty()) done(Result.failure(before ?: Said("No key opens this store.")))
            else onFido(d, { c -> ctapSecret(c, keys, salt, pin).let { Tapped.Ctap(it.first, it.second) } }, done)
        }
        if (challenge == null) ctap(null)
        else YubiOtpSession.create(d) { s ->
            runCatching { Tapped.Slot2(slot2(s.value, challenge, false)) as Tapped }.fold({ done(Result.success(it)) }, { ctap(it) })
        }
    }
