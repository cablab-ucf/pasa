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
import java.security.SecureRandom
import java.util.Base64

/*
 * Security keys by CTAP2 (FIDO2 without the network), its hmac-secret: the key holds a secret made on it that never leaves it,
 * and gives HMAC-SHA-256 of a salt under it. All of it is between this phone and the key, over NFC or
 * USB: no server, no account, no network; "pasa" below is a name on the key, not an address. Nothing
 * here or in Yubico's library opens a connection: android/no-network.sh checks both at every build.
 */
private const val RP = "pasa"

private fun rand(n: Int) = ByteArray(n).also { SecureRandom().nextBytes(it) }
private fun b64(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

/** What [use] makes of the next security key tapped (NFC) or plugged in (USB). */
private suspend fun <T> withFido(a: Activity, use: (Ctap2Client) -> T): T = withDevice(a) { d: YubiKeyDevice, done ->
    val run = { session: () -> Ctap2Session ->
        done(runCatching { use(Ctap2Client(session(), listOf(HmacSecretExtension(true)))) }.recoverCatching { throw told(it) })
    }
    if (d.supportsConnection(FidoConnection::class.java)) d.requestConnection(FidoConnection::class.java) { c -> run { Ctap2Session(c.value) } }
    else d.requestConnection(SmartCardConnection::class.java) { c -> run { Ctap2Session(c.value) } }
}

/** What went wrong with a security key, for someone holding it; a key that did not answer is left to be said as that. */
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

/** What a key is asked to make: a credential for pasa that gives secrets (hmac-secret), with its PIN ([uv]) or not. */
internal fun creation(uv: Boolean) = PublicKeyCredentialCreationOptions.fromMap(
    mapOf(
        "rp" to mapOf("id" to RP, "name" to RP),
        "user" to mapOf("id" to b64(rand(16)), "name" to RP, "displayName" to RP),
        "challenge" to b64(rand(32)),
        "pubKeyCredParams" to listOf(mapOf("type" to "public-key", "alg" to -7)),
        // Not one of those a key has room for only a few of: the store keeps its id.
        "authenticatorSelection" to mapOf("residentKey" to "discouraged", "userVerification" to if (uv) "required" else "discouraged"),
        "extensions" to mapOf("hmacCreateSecret" to true),
    ),
)

/** What a key is asked for: its secret for [salt], if it holds one of [creds]. */
internal fun request(creds: List<ByteArray>, salt: ByteArray, uv: Boolean) = PublicKeyCredentialRequestOptions.fromMap(
    mapOf(
        "challenge" to b64(rand(32)), "rpId" to RP,
        "allowCredentials" to creds.map { mapOf("type" to "public-key", "id" to b64(it)) },
        "userVerification" to if (uv) "required" else "discouraged",
        "extensions" to mapOf("hmacGetSecret" to mapOf("salt1" to b64(salt))),
    ),
)

/** The key's secret for [salt], and which of [creds] it is under: with its PIN ([uv]) or without, since the secret differs. */
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

/** A new credential on the key tapped, and its secret for [salt]: the credential, whether its PIN went with it, the secret. */
suspend fun fidoNew(a: Activity, salt: ByteArray, pin: String): Triple<ByteArray, Boolean, ByteArray> = withFido(a) { c ->
    val typed = pinOf(c, pin)
    val made = c.makeCredential(ClientDataProvider.fromHash(rand(32)), creation(typed != null), RP, typed, null, null)
    Triple(made.rawId, typed != null, secret(c, listOf(made.rawId), salt, typed != null, typed).second)
}

/** The secret of the key tapped, if it is one of [keys] (credential, whether its PIN goes with it): which, and the secret. */
suspend fun fidoSecret(a: Activity, keys: List<Pair<ByteArray, Boolean>>, salt: ByteArray, pin: String): Pair<ByteArray, ByteArray> = withFido(a) { c ->
    val typed = if (keys.any { it.second }) pinOf(c, pin) else null
    val got = secret(c, keys.map { it.first }, salt, typed != null, typed)
    // Added without its PIN and given one since (or the other way): its secret is another now.
    if (keys.first { it.first.contentEquals(got.first) }.second != (typed != null))
        throw Said("This key's PIN was set or removed since it was added: use the password, then add the key again.")
    got
}
