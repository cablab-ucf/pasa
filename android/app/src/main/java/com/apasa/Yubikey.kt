package com.apasa

import android.app.Activity
import android.content.Context
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.yubiotp.Slot
import com.yubico.yubikit.yubiotp.YubiOtpSession
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

/**
 * The YubiKey's HMAC-SHA1 (slot 2) of [challenge]: from a key held to the phone (NFC) or plugged in (USB),
 * whichever comes. With neither way open it says so at once ([NoKey]), not after a wait.
 */
suspend fun yubikey(a: Activity, challenge: ByteArray): ByteArray {
    val nfc = nfcOn(a)
    if (!nfc && !plugged(a)) throw NoKey(nfcOff(a))
    return suspendCancellableCoroutine { k ->
        val m = YubiKitManager(a)
        val stop = {
            runCatching { m.stopUsbDiscovery() }
            runCatching { m.stopNfcDiscovery(a) }
            Unit
        }
        val answer = { d: YubiKeyDevice ->
            YubiOtpSession.create(d) { session ->
                val r = runCatching { session.value.calculateHmacSha1(Slot.TWO, challenge, null) }
                stop()
                if (k.isActive) r.onSuccess { k.resume(it) }.onFailure { k.resumeWithException(it) }
            }
        }
        m.startUsbDiscovery(UsbConfiguration()) { answer(it) }
        if (nfc) m.startNfcDiscovery(NfcConfiguration(), a) { answer(it) }
        k.invokeOnCancellation { stop() }
    }
}
