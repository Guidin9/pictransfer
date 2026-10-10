package io.github.guidin9.warpshot

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Shader
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import java.util.concurrent.CompletableFuture
import uniffi.warpshot_ffi.DeviceEntry

/**
 * Debug-only screen gallery: every screen and state with sample data, no core,
 * no network. `--es screen <name>`; see [Render] for the names.
 *
 * `--es pair <qr text>` instead pairs with that code, as if scanned (the
 * emulator has no camera to scan with), and opens the main screen.
 */
class DemoActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        intent.getStringExtra("pair")?.let { qr ->
            Pairing.start(applicationContext, qr)
            startActivity(Intent(this, MainActivity::class.java))
            finish()
            return
        }
        val screen = intent.getStringExtra("screen") ?: "onboarding"
        setContent { WarpTheme { Surface(Modifier.fillMaxSize()) { Render(screen) } } }
    }
}

private val pc = DeviceEntry("a1", "DESKTOP-7Q2L9", 1uL, false)
private val laptop = DeviceEntry("b2", "Laptop", 1uL, false)

private fun sampleThumb() = Bitmap.createBitmap(320, 320, Bitmap.Config.ARGB_8888).also { b ->
    val c = Canvas(b)
    c.drawPaint(Paint().apply { shader = LinearGradient(0f, 0f, 320f, 320f, 0xFF7E57C2.toInt(), 0xFFFF8A65.toInt(), Shader.TileMode.CLAMP) })
    c.drawCircle(220f, 110f, 46f, Paint().apply { color = 0xFFFFF59D.toInt() })
    c.drawRect(0f, 230f, 320f, 320f, Paint().apply { color = 0xFF37474F.toInt() })
}.asImageBitmap()

private val sending = TransferState(1, false, pc.name, "Screenshot_20261010_142233.png", 6_100_000, 14_800_000, 9_400_000, running = true)
private val receiving = TransferState(2, true, pc.name, "", 0, 0, 0)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Render(screen: String) {
    val snackbar = remember { SnackbarHostState() }
    when (screen) {
        "onboarding" -> OnboardingScreen(PairState.Idle, {}, {})
        "onboarding_working" -> OnboardingScreen(PairState.Working, {}, {})
        "onboarding_failed" -> OnboardingScreen(
            PairState.Failed(androidx.compose.ui.res.stringResource(R.string.pair_err_invalid)),
            {},
            {},
        )
        "sas" -> OnboardingScreen(PairState.Confirm("K7Q-M2X", pc.name, CompletableFuture()), {}, {})
        "home" -> HomeScreen(listOf(pc), pc, "", {}, emptyList(), false, true, PairState.Idle, snackbar, HomeActions())
        "home_busy" -> {
            LaunchedEffect(Unit) { snackbar.showSnackbar("Sent to ${pc.name}.") }
            HomeScreen(
                listOf(pc, laptop), pc, "https://example.com/a/rather/long/link", {},
                listOf(sending, receiving), true, false, PairState.Idle, snackbar, HomeActions(),
            )
        }
        else -> {
            val (stage, preview, pcs) = when (screen) {
                "share_preparing" -> Triple(ShareStage.Preparing, SharePreview(R.drawable.ic_file, "Report final v3.pdf", "2.4 MB"), listOf(pc))
                "share_choose" -> Triple(
                    ShareStage.Choose,
                    SharePreview(R.drawable.ic_photos, "3 items", "18 MB", sampleThumb()),
                    listOf(pc, laptop),
                )
                "share_done" -> Triple(ShareStage.Ended(true, "Sent to ${pc.name}."), SharePreview(R.drawable.ic_image, sending.label, "14 MB", sampleThumb()), listOf(pc))
                "share_failed" -> Triple(
                    ShareStage.Ended(false, "Not sent to ${pc.name}. Your PC is offline."),
                    SharePreview(R.drawable.ic_image, sending.label, "14 MB", sampleThumb()),
                    listOf(pc),
                )
                "share_text" -> Triple(
                    ShareStage.Sending(3),
                    SharePreview(R.drawable.ic_notes, "Meeting moved to 15:30, room B204. Bring the printed slides and the adapter.", text = true),
                    listOf(pc),
                )
                "share_unpaired" -> Triple(ShareStage.Ended(false, "Open Warpshot and pair with your PC first.", openApp = true), null, emptyList())
                else -> Triple(ShareStage.Sending(1), SharePreview(R.drawable.ic_image, sending.label, "14 MB", sampleThumb()), listOf(pc))
            }
            HomeScreen(listOf(pc), pc, "", {}, emptyList(), false, true, PairState.Idle, snackbar, HomeActions())
            val sheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
            ModalBottomSheet(onDismissRequest = {}, sheetState = sheet) {
                ShareSheet(stage, preview, pcs, pcs.firstOrNull()?.id, if (stage is ShareStage.Sending) sending.copy(id = stage.id) else null, ShareActions())
            }
        }
    }
}
