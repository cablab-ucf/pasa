package com.apasa

/** libapasa.so (apasa-jni). Calls throw RuntimeException; run off the main thread. */
object Native {
    init { System.loadLibrary("apasa") }

    external fun challenge(dir: String): ByteArray?
    external fun open(dir: String, pw: ByteArray, chal: ByteArray?, resp: ByteArray?, create: Boolean): Long
    external fun quick(dir: String): ByteArray?
    external fun openQuick(dir: String, pin: ByteArray, resp: ByteArray): Long
    external fun quickOn(h: Long, pin: ByteArray, chal: ByteArray, resp: ByteArray)
    external fun quickOff(dir: String)
    external fun close(h: Long)
    external fun names(h: Long): String
    external fun get(h: Long, name: String): String
    external fun put(h: Long, name: String, body: String)
    external fun field(body: String, f: String): String
    external fun generate(len: Int, symbols: Boolean): String
    external fun speakable(words: Int, hyphens: Boolean, leet: Boolean): String
    external fun remove(h: Long, name: String)
    external fun rename(h: Long, from: String, to: String)
    external fun history(h: Long, name: String): String
    external fun files(h: Long, name: String): String
    external fun bytes(h: Long, name: String): ByteArray
    external fun keep(h: Long, name: String, body: ByteArray)
    external fun strength(pw: String): Int
    external fun times(h: Long, name: String): String
    external fun health(h: Long): String
    external fun stats(h: Long): String
    external fun pwnedKey(pw: String): String
    external fun pwnedCount(kept: String, text: String): Long
    external fun form(body: String): String
    external fun text(form: String): String
    external fun peers(dir: String): String
    external fun forget(dir: String, name: String)
    external fun pair(h: Long, name: String): String
    external fun join(dir: String, name: String, code: String, pw: String): String
    external fun sync(dir: String, news: Boolean): String
    external fun lane(dir: String): ByteArray
    external fun mailbox(dir: String, id: String)
    external fun wake(dir: String): String
}
