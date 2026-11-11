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
import com.yubico.yubikit.yubiotp.Slot
import com.yubico.yubikit.yubiotp.YubiOtpSession
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/** No key can be reached: NFC is off ([nfcOff]) or the phone has none, and no key is plugged in. */
class NoKey(val nfcOff: Boolean) : Exception(
    if (nfcOff) "NFC is off. Turn it on to tap the YubiKey, or plug the key in."
    else "This phone has no NFC: plug the YubiKey in.",
)

/** Whether the phone has NFC and it is switched off. */
fun nfcOff(c: Context) = NfcAdapter.getDefaultAdapter(c)?.isEnabled == false

private fun nfcOn(c: Context) = NfcAdapter.getDefaultAdapter(c)?.isEnabled == true

/** A YubiKey in the USB port (Yubico's vendor id). */
private fun plugged(c: Context) =
    c.getSystemService(UsbManager::class.java)?.deviceList?.values?.any { it.vendorId == 0x1050 } == true

/** Counts the waits for a key: an earlier one's late clean-up must not end a later one's listening. */
private val waits = AtomicInteger()

/**
 * The YubiKey's HMAC-SHA1 (slot 2) of [challenge]: from a key held to the phone (NFC) or plugged in (USB),
 * whichever comes. With neither way open it says so at once ([NoKey]), not after a wait.
 *
 * The app listens for the key until the answer is in, and for a key on NFC until it is lifted away: while
 * the app listens, Android does not open the web address a YubiKey carries. (Ending the listening as soon
 * as the key was seen lost the key mid-answer, "Tag was lost", and let that page open.)
 */
suspend fun yubikey(a: Activity, challenge: ByteArray): ByteArray {
    val nfc = nfcOn(a)
    if (!nfc && !plugged(a)) throw NoKey(nfcOff(a))
    val mine = waits.incrementAndGet()
    return suspendCancellableCoroutine { k ->
        val m = YubiKitManager(a)
        val stop = {
            runCatching { m.stopUsbDiscovery() }
            // Not if a later wait is listening by now.
            if (waits.get() == mine) runCatching { m.stopNfcDiscovery(a) }
            Unit
        }
        val answer = { d: YubiKeyDevice ->
            YubiOtpSession.create(d) { session ->
                val r = runCatching { session.value.calculateHmacSha1(Slot.TWO, challenge, null) }
                if (d is NfcYubiKeyDevice) d.remove { stop() } else stop()
                if (k.isActive) r.onSuccess { k.resume(it) }.onFailure { k.resumeWithException(Exception(said(it))) }
            }
        }
        m.startUsbDiscovery(UsbConfiguration()) { answer(it) }
        // The key's web address is not read: only its answer is wanted.
        if (nfc) {
            // Switched off since it was looked at: said as before the wait.
            runCatching { m.startNfcDiscovery(NfcConfiguration().skipNdefCheck(true), a) { answer(it) } }
                .onFailure { if (!plugged(a) && k.isActive) k.resumeWithException(NoKey(true)) }
        }
        k.invokeOnCancellation { stop() }
    }
}

/** What went wrong with the key, for someone holding it. */
private fun said(e: Throwable) = when {
    e is android.nfc.TagLostException || e.message?.contains("Tag was lost") == true ->
        "The key moved away too soon: hold it still against the phone until this is done."
    e is java.io.IOException -> "The key did not answer: hold it still against the phone, or plug it in. (${e.message})"
    else -> "The key refused: is its slot 2 set to HMAC-SHA1 challenge-response? (${e.message})"
}
