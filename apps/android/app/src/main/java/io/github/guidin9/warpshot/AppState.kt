package io.github.guidin9.warpshot

import android.content.Context
import android.content.Intent
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/** The app's own settings (the core keeps keys, the log and history). */
object Prefs {
    private fun p(ctx: Context) = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE)

    fun copyOnReceive(ctx: Context) = p(ctx).getBoolean("copy_on_receive", true)
    fun setCopyOnReceive(ctx: Context, on: Boolean) = p(ctx).edit().putBoolean("copy_on_receive", on).apply()

    fun keepHistory(ctx: Context) = p(ctx).getBoolean("history", true)
    fun setKeepHistory(ctx: Context, on: Boolean) = p(ctx).edit().putBoolean("history", on).apply()
}

/** Item kinds (protocol §8.4). */
object Kind {
    const val TEXT = 1uL
    const val IMAGE = 2uL
    const val FILE = 3uL

    fun ofName(name: String): ULong =
        if (name.substringAfterLast('.', "").lowercase() in setOf("png", "jpg", "jpeg", "webp", "gif")) IMAGE else FILE
}

/**
 * Transfer history in the core's encrypted store (history key, 30 days or
 * 200 rows), like the agent's. [changed] ticks when rows are added or removed.
 */
object HistoryLog {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val _changed = MutableStateFlow(0)
    val changed: StateFlow<Int> = _changed

    fun touch() {
        _changed.value++
    }

    fun add(
        ctx: Context,
        incoming: Boolean,
        peer: String,
        kind: ULong,
        size: Long,
        ok: Boolean,
        name: String? = null,
        uri: String? = null,
        text: String? = null,
    ) {
        if (!Prefs.keepHistory(ctx) || peer.isEmpty()) return
        val app = ctx.applicationContext
        scope.launch {
            val core = Core.get(app) ?: return@launch
            runCatching { core.historyAdd(incoming, peer, kind, size.coerceAtLeast(0).toULong(), ok, name, uri, text) }
            touch()
        }
    }

    /** A send's rows: one per file, or one for text. Sizes are read before the copies go. */
    fun sent(ctx: Context, peer: String, text: String?, files: List<Pair<String, Long>>, ok: Boolean) {
        if (text != null) {
            add(ctx, false, peer, Kind.TEXT, text.toByteArray().size.toLong(), ok, text = text)
        } else {
            files.forEach { (name, size) -> add(ctx, false, peer, Kind.ofName(name), size, ok, name = name) }
        }
    }

    fun sizes(paths: List<String>): List<Pair<String, Long>> = paths.map { File(it).let { f -> f.name to f.length() } }
}

/**
 * One sharing shortcut per paired PC (architecture §4): the PC shows up at the
 * top of Android's share sheet and a tap sends there at once.
 */
object Shortcuts {
    private const val CATEGORY = "io.github.guidin9.warpshot.category.SEND_TO_PC"
    private const val PREFIX = "pc-"

    fun sync(ctx: Context, pcs: List<uniffi.warpshot_ffi.DeviceEntry>) {
        runCatching {
            val keep = pcs.map { PREFIX + it.id }.toSet()
            val stale = ShortcutManagerCompat.getDynamicShortcuts(ctx).map { it.id }.filter { it !in keep }
            if (stale.isNotEmpty()) ShortcutManagerCompat.removeLongLivedShortcuts(ctx, stale)
            for (pc in pcs) {
                ShortcutManagerCompat.pushDynamicShortcut(
                    ctx,
                    ShortcutInfoCompat.Builder(ctx, PREFIX + pc.id)
                        .setShortLabel(pc.name)
                        .setLongLabel(ctx.getString(R.string.shortcut_long, pc.name))
                        .setIcon(IconCompat.createWithResource(ctx, R.mipmap.ic_shortcut_pc))
                        .setIntent(Intent(ctx, MainActivity::class.java).setAction(Intent.ACTION_MAIN))
                        .setLongLived(true)
                        .setCategories(setOf(CATEGORY))
                        .build(),
                )
            }
        }
    }

    /** The PC a share went to through its shortcut, if it did. */
    fun target(intent: Intent): String? =
        intent.getStringExtra(ShortcutManagerCompat.EXTRA_SHORTCUT_ID)?.takeIf { it.startsWith(PREFIX) }?.removePrefix(PREFIX)
}
