package com.apasa

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import kotlin.concurrent.thread
import org.pushir.Pushir

/** No network until the user turns this on. */
fun syncOn(c: Context) = c.getSharedPreferences("pasa", 0).getBoolean("sync", false)

fun push(c: Context) {
    val dir = store(c).path
    Pushir.start(c, "apasa", Native.lane(dir), onId = { Native.mailbox(dir, it) }) {
        thread { runCatching { Native.wake(dir) } }
    }
}

/** Disabled while sync is off: no boot or other app starts pushir here, so no network. */
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
