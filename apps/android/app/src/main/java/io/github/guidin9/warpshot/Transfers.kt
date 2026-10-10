package io.github.guidin9.warpshot

import android.os.SystemClock
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/** How a transfer ended. */
sealed interface Outcome {
    data object Done : Outcome
    data object Cancelled : Outcome
    data class Failed(val message: String) : Outcome
}

/** One transfer as the share card and the ongoing notification show it (roadmap 3 + 4b). */
data class TransferState(
    val id: Long,
    val incoming: Boolean,
    val peer: String,
    /** The first item's name; empty for text and for incoming transfers. */
    val label: String,
    val done: Long = 0,
    val total: Long = 0,
    val bytesPerSec: Long = 0,
    /** Items accepted and data flowing (the first progress report arrived). */
    val running: Boolean = false,
    val outcome: Outcome? = null,
    val endedAt: Long = 0,
) {
    val fraction: Float get() = if (total > 0) (done.toFloat() / total).coerceIn(0f, 1f) else 0f
}

/**
 * Process-wide transfer state. The core reports progress from its own threads
 * (via [CoreObserver]); everything here is thread-safe. Ids are ours: they are
 * passed to the core's send/receive calls and to `cancelTransfer`.
 */
object Transfers {
    private val nextId = AtomicLong(SystemClock.elapsedRealtime())
    private val _state = MutableStateFlow<Map<Long, TransferState>>(emptyMap())
    val state: StateFlow<Map<Long, TransferState>> = _state

    /** Transfers a visible screen reports itself; the service then skips the result notification. */
    val watched: MutableSet<Long> = ConcurrentHashMap.newKeySet()

    fun newId(): Long = nextId.incrementAndGet()

    fun start(id: Long, incoming: Boolean, peer: String, label: String) = _state.update { m ->
        // Finished entries are kept briefly for the screens that show their result.
        val now = SystemClock.elapsedRealtime()
        m.filterValues { it.outcome == null || now - it.endedAt < 60_000 } +
            (id to TransferState(id, incoming, peer, label))
    }

    fun progress(id: Long, done: Long, total: Long, bytesPerSec: Long) = _state.update { m ->
        val t = m[id] ?: return@update m
        m + (id to t.copy(done = done, total = total, bytesPerSec = bytesPerSec, running = true))
    }

    fun finish(id: Long, outcome: Outcome) = _state.update { m ->
        val t = m[id] ?: return@update m
        m + (id to t.copy(outcome = outcome, endedAt = SystemClock.elapsedRealtime()))
    }

    fun active(): List<TransferState> = _state.value.values.filter { it.outcome == null }.sortedBy { it.id }
}
