package com.apasa

import android.app.Application
import android.content.Context
import kotlin.concurrent.thread
import org.irpush.Irpush

/** Whether the user turned sync on: no network before that. */
fun syncOn(c: Context) = c.getSharedPreferences("pasa", 0).getBoolean("sync", false)

/** Woken through the phone's one irpush connection: a fresh wake from a
 *  paired device syncs. irpush hands the wake over unopened. */
fun push(c: Context) {
    val dir = store(c).path
    Irpush.start(c, "apasa", Native.slot(dir), onId = { Native.mailbox(dir, it) }) { m ->
        thread { runCatching { Native.wake(dir, m) } }
    }
}

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        if (syncOn(this)) push(this)
    }
}
