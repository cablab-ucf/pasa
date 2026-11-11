package com.apasa

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import kotlin.concurrent.thread
import org.pushir.Pushir

/** Whether the user turned sync on: no network before that. */
fun syncOn(c: Context) = c.getSharedPreferences("pasa", 0).getBoolean("sync", false)

/** Woken through the phone's one pushir connection: a message on pasa's
 *  lane (a paired device's wake, or the connection back from a gap) syncs.
 *  Whoever holds the connection hands it over unopened. */
fun push(c: Context) {
    val dir = store(c).path
    Pushir.start(c, "apasa", Native.lane(dir), onId = { Native.mailbox(dir, it) }) {
        thread { runCatching { Native.wake(dir) } }
    }
}

/** pushir's service is this app's to run only while sync is on: off, neither a boot nor another app starts it. */
fun broker(c: Context, on: Boolean) = c.packageManager.setComponentEnabledSetting(
    ComponentName(c, "org.pushir.Broker"),
    if (on) PackageManager.COMPONENT_ENABLED_STATE_ENABLED else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
    PackageManager.DONT_KILL_APP,
)

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        broker(this, syncOn(this))
        if (syncOn(this)) push(this)
    }
}
