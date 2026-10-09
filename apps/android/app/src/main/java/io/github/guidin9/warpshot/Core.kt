package io.github.guidin9.warpshot

import android.content.Context
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.warpshot_ffi.PlatformKeystore
import uniffi.warpshot_ffi.WarpException
import uniffi.warpshot_ffi.Warpshot
import uniffi.warpshot_ffi.qrServerUrl

/**
 * Wraps the core's device keys with a non-exportable AES-256-GCM key in the
 * Android Keystore (StrongBox when available). The label is bound as AAD.
 * Blob layout: 12-byte IV || ciphertext+tag.
 */
class AndroidKeystore : PlatformKeystore {
    private val alias = "warpshot-wrap"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        fun gen(strongBox: Boolean): SecretKey {
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(strongBox)
                .build()
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                .apply { init(spec) }
                .generateKey()
        }
        return try {
            gen(true)
        } catch (_: Exception) {
            gen(false)
        }
    }

    override fun wrap(label: String, plain: ByteArray): ByteArray = try {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        c.updateAAD(label.toByteArray())
        c.iv + c.doFinal(plain)
    } catch (_: Exception) {
        throw WarpException.Storage()
    }

    override fun unwrap(label: String, wrapped: ByteArray): ByteArray = try {
        require(wrapped.size > 12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, wrapped, 0, 12))
        c.updateAAD(label.toByteArray())
        c.doFinal(wrapped, 12, wrapped.size - 12)
    } catch (_: Exception) {
        throw WarpException.Storage()
    }
}

/** Process-wide access to the Rust core. */
object Core {
    private const val PREFS = "warpshot"
    private var instance: Warpshot? = null

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun deviceName(ctx: Context): String =
        Settings.Global.getString(ctx.contentResolver, Settings.Global.DEVICE_NAME)
            ?: "${Build.MANUFACTURER} ${Build.MODEL}"

    /** The core, if a server is known (after the first pairing). */
    @Synchronized
    fun get(ctx: Context): Warpshot? {
        instance?.let { return it }
        val url = prefs(ctx).getString("server_url", null) ?: return null
        return open(ctx, url)
    }

    @Synchronized
    private fun open(ctx: Context, url: String): Warpshot {
        val dir = ctx.filesDir.resolve("core").apply { mkdirs() }
        val w = Warpshot.open(dir.path, deviceName(ctx), url, AndroidKeystore())
        instance = w
        return w
    }

    /** Opens the core for the server named in a pairing QR code. */
    @Synchronized
    fun forQr(ctx: Context, qr: String): Warpshot? {
        val url = qrServerUrl(qr) ?: return null
        val saved = prefs(ctx).getString("server_url", null)
        if (saved != null && saved != url) return null // another deployment: not supported
        prefs(ctx).edit().putString("server_url", url).apply()
        return instance ?: open(ctx, url)
    }

    var defaultTarget: String? = null
}

fun errorText(e: Throwable): String = when (e) {
    is WarpException.Offline -> "Your PC is offline."
    is WarpException.NotPaired -> "Pair with your PC first."
    is WarpException.Rejected -> "The PC refused the transfer."
    is WarpException.Network -> "Network error (${e.code})."
    is WarpException.Server -> "Server error (${e.code})."
    is WarpException.Invalid -> "Invalid input."
    is WarpException.Storage -> "Storage error."
    else -> "Error: ${e.javaClass.simpleName}"
}
