package com.apasa

import android.app.Activity
import android.content.Context
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.yubiotp.HmacSha1SlotConfiguration
import com.yubico.yubikit.yubiotp.Slot
import com.yubico.yubikit.yubiotp.YubiOtpSession
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

class NoKey(val nfcOff: Boolean) : Exception(
    if (nfcOff) "NFC is off. Turn it on to tap the YubiKey, or plug the key in."
    else "This phone has no NFC: plug the YubiKey in.",
)

fun nfcOff(c: Context) = NfcAdapter.getDefaultAdapter(c)?.isEnabled == false

private fun nfcOn(c: Context) = NfcAdapter.getDefaultAdapter(c)?.isEnabled == true

/** 0x1050: Yubico's USB vendor id. */
private fun plugged(c: Context) =
    c.getSystemService(UsbManager::class.java)?.deviceList?.values?.any { it.vendorId == 0x1050 } == true

/** An earlier wait's late clean-up must not stop a later wait's NFC listening. */
private val waits = AtomicInteger()

suspend fun yubikey(a: Activity, challenge: ByteArray, enroll: Boolean = false): ByteArray = withKey(a) { slot2(it, challenge, enroll) }

internal fun slot2(s: YubiOtpSession, challenge: ByteArray, enroll: Boolean): ByteArray {
    // An empty slot answers nonsense rather than failing: ask first, where the key can say.
    if (runCatching { !s.configurationState.isConfigured(Slot.TWO) }.getOrDefault(false)) throw Empty(enroll)
    return s.calculateHmacSha1(Slot.TWO, challenge, null)
}

/** Only into a slot the key reports empty: never over one in use, nor where it cannot say. */
suspend fun writeKey(a: Activity, secret: ByteArray): Unit = withKey(a) { s ->
    if (runCatching { s.configurationState.isConfigured(Slot.TWO) }.getOrDefault(true))
        throw InUse()
    s.putConfiguration(Slot.TWO, HmacSha1SlotConfiguration(secret), null, null)
}

private suspend fun <T> withKey(a: Activity, use: (YubiOtpSession) -> T): T =
    withDevice(a) { d, done -> YubiOtpSession.create(d) { session -> done(runCatching { use(session.value) }) } }

/** NFC listening lasts until the key is lifted: while it does, Android opens no URL the key carries,
 *  and stopping sooner loses the key mid-answer ("Tag was lost"). */
suspend fun <T> withDevice(a: Activity, open: (YubiKeyDevice, (Result<T>) -> Unit) -> Unit): T {
    val nfc = nfcOn(a)
    if (!nfc && !plugged(a)) throw NoKey(nfcOff(a))
    val mine = waits.incrementAndGet()
    return suspendCancellableCoroutine { k ->
        val m = YubiKitManager(a)
        val stop = {
            runCatching { m.stopUsbDiscovery() }
            if (waits.get() == mine) runCatching { m.stopNfcDiscovery(a) }
            Unit
        }
        val answer = { d: YubiKeyDevice ->
            open(d) { r ->
                if (d is NfcYubiKeyDevice) d.remove { stop() } else stop()
                if (k.isActive) r.onSuccess { k.resume(it) }.onFailure { k.resumeWithException(Exception(said(it))) }
            }
        }
        m.startUsbDiscovery(UsbConfiguration()) { answer(it) }
        if (nfc) {
            runCatching { m.startNfcDiscovery(NfcConfiguration().skipNdefCheck(true), a) { answer(it) } }
                .onFailure { if (!plugged(a) && k.isActive) k.resumeWithException(NoKey(true)) }
        }
        k.invokeOnCancellation { stop() }
    }
}

internal class Empty(val enroll: Boolean) : Exception()
private class InUse : Exception()

/** A message already fit for the user. */
class Said(text: String) : Exception(text)

private fun said(e: Throwable): String = when {
    e is Said -> e.message!!
    e is android.nfc.TagLostException || e.message?.contains("Tag was lost") == true ->
        "The key moved away too soon: hold it still against the phone until this is done."
    e is java.io.IOException -> "The key did not answer: hold it still against the phone, or plug it in. (${e.message})"
    e is Empty && e.enroll -> "$EMPTY_KEY It can be set up here: a new secret is written to it."
    e is Empty -> "Slot 2 of this YubiKey is empty: it is not a key this store was made with."
    e is InUse -> "Slot 2 of this YubiKey is in use, or the key cannot say: nothing was written to it."
    e is com.yubico.yubikit.core.application.BadResponseException ->
        "Slot 2 of this YubiKey holds something other than an HMAC-SHA1 challenge-response secret (a Yubico OTP or a static password?): its answer was not 20 bytes. (${e.message})"
    else -> "The key refused: is its slot 2 set to HMAC-SHA1 challenge-response? (${e.message})"
}
