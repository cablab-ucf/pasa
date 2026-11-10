package com.apasa

/** libapasa.so (apasa-jni). Calls throw RuntimeException; run off the main thread. */
object Native {
    init { System.loadLibrary("apasa") }

    external fun challenge(dir: String): ByteArray?
    external fun open(dir: String, pw: ByteArray, chal: ByteArray?, resp: ByteArray?, create: Boolean): Long
    external fun close(h: Long)
    external fun names(h: Long): String
    external fun get(h: Long, name: String): String
    external fun put(h: Long, name: String, body: String)
    external fun field(body: String, f: String): String
    external fun generate(len: Int): String
    external fun join(dir: String, name: String, code: String, pw: String): String
    external fun sync(dir: String, news: Boolean): String
    external fun lane(dir: String): ByteArray
    external fun mailbox(dir: String, id: String)
    external fun wake(dir: String): String
}
