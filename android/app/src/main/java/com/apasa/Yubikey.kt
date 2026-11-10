package com.apasa

import android.app.Activity
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.yubiotp.Slot
import com.yubico.yubikit.yubiotp.YubiOtpSession
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/** The YubiKey's HMAC-SHA1 (slot 2) of [challenge], over NFC. */
suspend fun yubikey(a: Activity, challenge: ByteArray): ByteArray = suspendCancellableCoroutine { k ->
    val m = YubiKitManager(a)
    m.startNfcDiscovery(NfcConfiguration(), a) { d ->
        d.requestConnection(SmartCardConnection::class.java) { r ->
            m.stopNfcDiscovery(a)
            runCatching { YubiOtpSession(r.value).calculateHmacSha1(Slot.TWO, challenge, null) }
                .onSuccess { if (k.isActive) k.resume(it) }
                .onFailure { if (k.isActive) k.resumeWithException(it) }
        }
    }
    k.invokeOnCancellation { m.stopNfcDiscovery(a) }
}
