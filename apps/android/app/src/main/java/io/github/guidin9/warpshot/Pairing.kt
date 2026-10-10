package io.github.guidin9.warpshot

import android.content.Context
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import uniffi.warpshot_ffi.PairConfirm
import uniffi.warpshot_ffi.WarpException

/** Where a pairing (protocol §5, scanner side) stands, as the main screen shows it. */
sealed interface PairState {
    data object Idle : PairState
    data object Working : PairState

    /** The core asks whether both screens show [sas]; answered with [Pairing.answer]. */
    data class Confirm(val sas: String, val peer: String, val answer: CompletableFuture<Boolean>) : PairState
    data class Done(val peer: String) : PairState
    data class Failed(val message: String) : PairState
}

/**
 * Process-wide pairing, so a rotation or a recreated screen doesn't lose a
 * pairing in progress. The core asks the SAS question on its own thread and
 * blocks until [answer] (or 90 s).
 */
object Pairing {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val _state = MutableStateFlow<PairState>(PairState.Idle)
    val state: StateFlow<PairState> = _state

    fun start(ctx: Context, qr: String) {
        val s = _state.value
        if (s is PairState.Working || s is PairState.Confirm) return
        _state.value = PairState.Working
        val app = ctx.applicationContext
        scope.launch {
            // Opening the core loads the native library and the database: off the UI thread.
            val core = Core.forQr(app, qr)
            if (core == null) {
                _state.value = PairState.Failed(app.getString(R.string.pair_not_code))
                return@launch
            }
            val confirm = object : PairConfirm {
                override fun confirm(sas: String, peerName: String, peerPlatform: ULong): Boolean {
                    val q = PairState.Confirm(sas, peerName, CompletableFuture())
                    _state.value = q
                    val ok = runCatching { q.answer.get(90, TimeUnit.SECONDS) }.getOrDefault(false)
                    _state.value = PairState.Working
                    return ok
                }
            }
            _state.value = try {
                val pc = core.pairScan(qr, confirm)
                runCatching { core.sync() }
                val name = runCatching { core.devices() }.getOrNull()?.firstOrNull { it.id == pc }?.name
                PairState.Done(name ?: app.getString(R.string.your_pc))
            } catch (e: Exception) {
                PairState.Failed(pairError(app, e))
            }
        }
    }

    fun answer(match: Boolean) {
        (_state.value as? PairState.Confirm)?.answer?.complete(match)
    }

    /** A failure or success was shown; back to idle. */
    fun reset() {
        val s = _state.value
        if (s is PairState.Done || s is PairState.Failed) _state.value = PairState.Idle
    }

    /** Scanner errors (the GMS code scanner, before the core is involved). */
    fun failed(message: String) {
        _state.value = PairState.Failed(message)
    }

    private fun pairError(ctx: Context, e: Exception): String = when (e) {
        is WarpException.Invalid -> ctx.getString(R.string.pair_err_invalid)
        is WarpException.Rejected, is WarpException.Cancelled -> ctx.getString(R.string.pair_err_rejected)
        is WarpException.Network, is WarpException.Offline -> ctx.getString(R.string.pair_err_network)
        else -> ctx.getString(R.string.pairing_failed, errorText(ctx, e))
    }
}
