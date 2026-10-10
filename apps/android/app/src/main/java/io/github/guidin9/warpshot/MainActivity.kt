package io.github.guidin9.warpshot

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LifecycleResumeEffect
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.warpshot_ffi.DeviceEntry

class MainActivity : ComponentActivity() {
    /** Sends started on this screen; while it is visible it reports their results itself. */
    private val mine: MutableSet<Long> = ConcurrentHashMap.newKeySet()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent { WarpTheme { Surface(Modifier.fillMaxSize()) { MainScreen(mine) } } }
    }

    override fun onStart() {
        super.onStart()
        Transfers.watched += mine
    }

    override fun onStop() {
        // Not visible any more: results of these sends become notifications.
        Transfers.watched -= mine
        mine.clear()
        super.onStop()
    }
}

/** Main-screen actions, so the screens themselves stay stateless (and previewable). */
class HomeActions(
    val sendText: () -> Unit = {},
    val paste: () -> Unit = {},
    val pickPhotos: () -> Unit = {},
    val pickFiles: () -> Unit = {},
    val selectTarget: (String) -> Unit = {},
    val cancel: (Long) -> Unit = {},
    val pairAnother: () -> Unit = {},
    val enableNotifications: () -> Unit = {},
)

@Composable
fun MainScreen(mine: MutableSet<Long>) {
    val ctx = LocalContext.current
    val activity = LocalActivity.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    // null until the core has been asked: avoids flashing the pairing screen.
    var devices by remember { mutableStateOf<List<DeviceEntry>?>(null) }
    var target by remember { mutableStateOf<String?>(null) }
    var draft by rememberSaveable { mutableStateOf("") }
    var preparing by remember { mutableIntStateOf(0) }
    var notificationsOn by remember { mutableStateOf(true) }
    val pairing by Pairing.state.collectAsState()
    val transfers by Transfers.state.collectAsState()
    val focus = LocalFocusManager.current

    suspend fun refresh() {
        val core = withContext(Dispatchers.IO) { Core.get(ctx) }
        if (core == null) {
            devices = emptyList()
            return
        }
        devices = runCatching { core.devices() }.getOrDefault(emptyList())
        // Then the server's log, in case a device was added or removed elsewhere.
        if (runCatching { core.sync() }.isSuccess) {
            devices = runCatching { core.devices() }.getOrDefault(devices.orEmpty())
        }
    }

    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        notificationsOn = NotificationManagerCompat.from(ctx).areNotificationsEnabled()
    }

    fun enableNotifications() {
        val perm = Manifest.permission.POST_NOTIFICATIONS
        val prefs = ctx.getSharedPreferences("ui", Context.MODE_PRIVATE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(ctx, perm) != PackageManager.PERMISSION_GRANTED
        ) {
            // Android asks at most twice; after that only the settings page can turn them on.
            val asked = prefs.getBoolean("asked_notifications", false)
            if (!asked || (activity != null && ActivityCompat.shouldShowRequestPermissionRationale(activity, perm))) {
                prefs.edit().putBoolean("asked_notifications", true).apply()
                notifPermission.launch(perm)
                return
            }
        }
        runCatching {
            ctx.startActivity(
                Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName),
            )
        }
    }

    LifecycleResumeEffect(Unit) {
        notificationsOn = NotificationManagerCompat.from(ctx).areNotificationsEnabled()
        val job = scope.launch { refresh() }
        onPauseOrDispose { job.cancel() }
    }

    val pcs = devices.orEmpty().filter { !it.me }
    val paired = pcs.isNotEmpty()
    LaunchedEffect(paired) {
        if (paired) Push.ensureRegistered(ctx)
    }

    // Pairing results: a new PC appears; failures show where the user looks.
    LaunchedEffect(pairing) {
        when (val p = pairing) {
            is PairState.Done -> {
                refresh() // the progress stays up until the new PC is listed
                Pairing.reset()
                if (!NotificationManagerCompat.from(ctx).areNotificationsEnabled()) enableNotifications()
                snackbar.showSnackbar(ctx.getString(R.string.paired_with, p.peer))
            }
            is PairState.Failed -> if (paired) {
                Pairing.reset()
                snackbar.showSnackbar(p.message)
            }
            else -> {}
        }
    }

    // Results of sends started here, as a snackbar instead of a notification.
    LaunchedEffect(Unit) {
        Transfers.state.collect { all ->
            for (id in mine.toList()) {
                val t = all[id] ?: continue
                val outcome = t.outcome ?: continue
                mine -= id
                Transfers.watched -= id
                val msg = when (outcome) {
                    Outcome.Done -> ctx.getString(R.string.sent_to, t.peer)
                    Outcome.Cancelled -> ctx.getString(R.string.cancelled)
                    is Outcome.Failed -> ctx.getString(R.string.not_sent_reason, t.peer, outcome.message)
                }
                launch { snackbar.showSnackbar(msg) }
            }
        }
    }

    fun scan() {
        Pairing.reset()
        val opts = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(ctx, opts).startScan()
            .addOnSuccessListener { code -> code.rawValue?.let { Pairing.start(ctx, it) } }
            .addOnFailureListener {
                Pairing.failed(ctx.getString(R.string.scanner_unavailable, it.javaClass.simpleName))
            }
    }

    val pc = pcs.firstOrNull { it.id == target } ?: Core.target(ctx, pcs)

    /** Starts a send in [TransferService]; false (and a snackbar) if Android refused. */
    fun handOver(label: String, text: String?, paths: List<String>): Boolean {
        val to = pc ?: return false
        val id = Transfers.newId()
        mine += id
        Transfers.watched += id
        return try {
            TransferService.send(ctx, id, to.id, to.name, label, text, paths)
            true
        } catch (_: Exception) {
            mine -= id
            Transfers.watched -= id
            Transfers.finish(id, Outcome.Failed(ctx.getString(R.string.start_not_allowed)))
            Outgoing.delete(ctx, paths)
            scope.launch { snackbar.showSnackbar(ctx.getString(R.string.start_failed)) }
            false
        }
    }

    fun sendUris(uris: List<Uri>) {
        if (uris.isEmpty() || pc == null) return
        scope.launch {
            preparing++
            val files = withContext(Dispatchers.IO) { uris.mapNotNull { Outgoing.copy(ctx, it) } }
            preparing--
            if (files.isEmpty()) {
                snackbar.showSnackbar(ctx.getString(R.string.cant_read_shared))
            } else {
                handOver(Outgoing.label(files), null, files.map { it.path })
            }
        }
    }

    val pickMedia = rememberLauncherForActivityResult(ActivityResultContracts.PickMultipleVisualMedia(50)) { sendUris(it) }
    val pickFiles = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { sendUris(it) }

    val actions = HomeActions(
        sendText = {
            if (draft.isNotBlank() && handOver("", draft, emptyList())) {
                draft = ""
                focus.clearFocus() // closes the keyboard: the progress and the result show below
            }
        },
        paste = {
            val clip = ctx.getSystemService(ClipboardManager::class.java)?.primaryClip
            val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString()
            if (text.isNullOrEmpty()) {
                scope.launch { snackbar.showSnackbar(ctx.getString(R.string.clipboard_empty)) }
            } else {
                draft = text
            }
        },
        pickPhotos = {
            pickMedia.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo))
        },
        pickFiles = { pickFiles.launch(arrayOf("*/*")) },
        selectTarget = {
            target = it
            Core.setTarget(ctx, it)
        },
        cancel = { TransferService.cancel(ctx, it) },
        pairAnother = { scan() },
        enableNotifications = { enableNotifications() },
    )

    when {
        devices == null -> {}
        pc == null -> OnboardingScreen(pairing, onScan = { scan() }, onAnswer = Pairing::answer)
        else -> {
            HomeScreen(
                pcs = pcs,
                target = pc,
                draft = draft,
                onDraft = { draft = it },
                transfers = transfers.values.filter { it.outcome == null }.sortedBy { it.id },
                preparing = preparing > 0,
                notificationsOn = notificationsOn,
                pairing = pairing,
                snackbar = snackbar,
                actions = actions,
            )
            (pairing as? PairState.Confirm)?.let { SasDialog(it, Pairing::answer) }
        }
    }
}

// ---------------------------------------------------------------- onboarding

@Composable
fun OnboardingScreen(state: PairState, onScan: () -> Unit, onAnswer: (Boolean) -> Unit) {
    Column(Modifier.fillMaxSize().safeDrawingPadding()) {
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 24.dp),
        ) {
            Spacer(Modifier.height(40.dp))
            AppMark(64.dp)
            Spacer(Modifier.height(20.dp))
            Text(
                stringResource(R.string.app_name),
                style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.onb_tagline),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(28.dp))
            Card(
                shape = RoundedCornerShape(28.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
            ) {
                Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(18.dp)) {
                    Text(stringResource(R.string.onb_steps_title), style = MaterialTheme.typography.titleMedium)
                    Step(1, stringResource(R.string.onb_step1))
                    Step(2, stringResource(R.string.onb_step2))
                    Step(3, stringResource(R.string.onb_step3))
                }
            }
            Spacer(Modifier.height(20.dp))
            Row(verticalAlignment = Alignment.Top) {
                Icon(
                    painterResource(R.drawable.ic_lock),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(16.dp).padding(top = 2.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.onb_privacy),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(16.dp))
        }
        Column(Modifier.padding(start = 24.dp, end = 24.dp, top = 8.dp, bottom = 16.dp)) {
            when (state) {
                PairState.Working, is PairState.Confirm, is PairState.Done -> PairingProgress()
                is PairState.Failed -> {
                    Card(
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                    ) {
                        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.Top) {
                            Icon(
                                painterResource(R.drawable.ic_error),
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onErrorContainer,
                                modifier = Modifier.size(20.dp),
                            )
                            Spacer(Modifier.width(12.dp))
                            Text(
                                state.message,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                        }
                    }
                    Spacer(Modifier.height(12.dp))
                    ScanButton(stringResource(R.string.try_again), onScan)
                }
                else -> ScanButton(stringResource(R.string.pair_with_pc), onScan)
            }
        }
    }
    if (state is PairState.Confirm) SasDialog(state, onAnswer)
}

@Composable
private fun Step(n: Int, text: String) {
    Row(verticalAlignment = Alignment.Top) {
        Box(Modifier.size(28.dp), contentAlignment = Alignment.Center) {
            Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primary, modifier = Modifier.fillMaxSize()) {}
            Text(
                n.toString(),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onPrimary,
            )
        }
        Spacer(Modifier.width(14.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 4.dp))
    }
}

@Composable
private fun ScanButton(label: String, onClick: () -> Unit) {
    Button(onClick = onClick, modifier = Modifier.fillMaxWidth().height(56.dp)) {
        Icon(painterResource(R.drawable.ic_qr), contentDescription = null, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(10.dp))
        Text(label, style = MaterialTheme.typography.titleSmall)
    }
}

@Composable
private fun PairingProgress(modifier: Modifier = Modifier) {
    Row(modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(Modifier.size(28.dp), strokeWidth = 3.dp)
        Spacer(Modifier.width(16.dp))
        Column {
            Text(stringResource(R.string.pairing), style = MaterialTheme.typography.titleSmall)
            Text(
                stringResource(R.string.pairing_wait),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** The short authentication string (protocol §5.3), large enough to compare at a glance. */
@Composable
fun SasDialog(q: PairState.Confirm, onAnswer: (Boolean) -> Unit) {
    AlertDialog(
        onDismissRequest = {},
        icon = { Icon(painterResource(R.drawable.ic_lock), contentDescription = null) },
        title = { Text(stringResource(R.string.confirm_pairing), textAlign = TextAlign.Center) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text(stringResource(R.string.confirm_pairing_body, q.peer))
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        q.sas,
                        style = MaterialTheme.typography.displaySmall,
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 2.sp,
                        textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.padding(vertical = 16.dp),
                    )
                }
            }
        },
        confirmButton = { Button(onClick = { onAnswer(true) }) { Text(stringResource(R.string.codes_match)) } },
        dismissButton = { TextButton(onClick = { onAnswer(false) }) { Text(stringResource(R.string.codes_differ)) } },
    )
}

// ---------------------------------------------------------------- home

@Composable
fun HomeScreen(
    pcs: List<DeviceEntry>,
    target: DeviceEntry,
    draft: String,
    onDraft: (String) -> Unit,
    transfers: List<TransferState>,
    preparing: Boolean,
    notificationsOn: Boolean,
    pairing: PairState,
    snackbar: SnackbarHostState,
    actions: HomeActions,
) {
    Scaffold(
        topBar = { HomeTopBar(actions.pairAnother) },
        snackbarHost = { SnackbarHost(snackbar) },
        // With the keyboard: the list ends and the snackbar sits above it.
        contentWindowInsets = WindowInsets.safeDrawing,
    ) { pad ->
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = pad.calculateTopPadding() + 4.dp,
                bottom = pad.calculateBottomPadding() + 24.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (pairing == PairState.Working || pairing is PairState.Confirm) {
                item { Section { PairingProgress() } }
            }
            item { SendCard(pcs, target, draft, onDraft, preparing, actions) }
            if (transfers.isNotEmpty() || preparing) {
                item {
                    Section {
                        Text(stringResource(R.string.in_progress), style = MaterialTheme.typography.titleMedium)
                        if (preparing) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                                Spacer(Modifier.width(12.dp))
                                Text(stringResource(R.string.preparing), style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                        transfers.forEach { t -> TransferRow(t, onCancel = { actions.cancel(t.id) }) }
                    }
                }
            }
            if (!notificationsOn) item { NotificationsCard(actions.enableNotifications) }
            item { TipsCard() }
        }
    }
}

@Composable
private fun HomeTopBar(onPairAnother: () -> Unit) {
    var menu by remember { mutableStateOf(false) }
    Row(
        Modifier.fillMaxWidth().statusBarsPadding().padding(start = 20.dp, end = 4.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AppMark(32.dp)
        Spacer(Modifier.width(12.dp))
        Text(
            stringResource(R.string.app_name),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.weight(1f),
        )
        Box {
            IconButton(onClick = { menu = true }) {
                Icon(painterResource(R.drawable.ic_more_vert), contentDescription = stringResource(R.string.more))
            }
            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.pair_another)) },
                    leadingIcon = { Icon(painterResource(R.drawable.ic_add), contentDescription = null) },
                    onClick = {
                        menu = false
                        onPairAnother()
                    },
                )
            }
        }
    }
}

/** A rounded surface-container card with the home screen's spacing. */
@Composable
private fun Section(content: @Composable () -> Unit) {
    Card(
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) { content() }
    }
}

@Composable
private fun SendCard(
    pcs: List<DeviceEntry>,
    target: DeviceEntry,
    draft: String,
    onDraft: (String) -> Unit,
    preparing: Boolean,
    actions: HomeActions,
) = Section {
    Row(verticalAlignment = Alignment.CenterVertically) {
        IconTile(
            R.drawable.ic_computer,
            size = 52.dp,
            container = MaterialTheme.colorScheme.primaryContainer,
            tint = MaterialTheme.colorScheme.onPrimaryContainer,
        )
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(
                stringResource(R.string.sending_target),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                target.name,
                style = MaterialTheme.typography.titleLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    painterResource(R.drawable.ic_lock),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(12.dp),
                )
                Spacer(Modifier.width(4.dp))
                Text(
                    stringResource(R.string.e2e),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
    if (pcs.size > 1) {
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            pcs.forEach { d ->
                FilterChip(
                    selected = d.id == target.id,
                    onClick = { actions.selectTarget(d.id) },
                    label = { Text(d.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    leadingIcon = {
                        Icon(painterResource(R.drawable.ic_computer), contentDescription = null, modifier = Modifier.size(18.dp))
                    },
                )
            }
        }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        BigAction(R.drawable.ic_photos, stringResource(R.string.photos), !preparing, actions.pickPhotos, Modifier.weight(1f))
        BigAction(R.drawable.ic_folder, stringResource(R.string.files), !preparing, actions.pickFiles, Modifier.weight(1f))
    }
    OutlinedTextField(
        value = draft,
        onValueChange = onDraft,
        placeholder = { Text(stringResource(R.string.text_hint)) },
        shape = RoundedCornerShape(20.dp),
        maxLines = 6,
        modifier = Modifier.fillMaxWidth(),
        trailingIcon = {
            if (draft.isBlank()) {
                IconButton(onClick = actions.paste) {
                    Icon(painterResource(R.drawable.ic_paste), contentDescription = stringResource(R.string.paste))
                }
            } else {
                FilledIconButton(onClick = actions.sendText, modifier = Modifier.padding(end = 4.dp)) {
                    Icon(
                        painterResource(R.drawable.ic_send),
                        contentDescription = stringResource(R.string.send),
                        modifier = Modifier.size(20.dp),
                    )
                }
            }
        },
    )
}

@Composable
private fun BigAction(icon: Int, label: String, enabled: Boolean, onClick: () -> Unit, modifier: Modifier) {
    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = modifier.height(96.dp),
    ) {
        Column(
            Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(painterResource(icon), contentDescription = null, modifier = Modifier.size(28.dp))
            Spacer(Modifier.height(8.dp))
            Text(label, style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun NotificationsCard(onEnable: () -> Unit) {
    Card(
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    painterResource(R.drawable.ic_notifications),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onTertiaryContainer,
                )
                Spacer(Modifier.width(12.dp))
                Text(
                    stringResource(R.string.notif_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                )
            }
            Text(
                stringResource(R.string.notif_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onTertiaryContainer,
            )
            FilledTonalButton(
                onClick = onEnable,
                modifier = Modifier.align(Alignment.End),
                colors = ButtonDefaults.filledTonalButtonColors(
                    containerColor = MaterialTheme.colorScheme.tertiary,
                    contentColor = MaterialTheme.colorScheme.onTertiary,
                ),
            ) { Text(stringResource(R.string.notif_turn_on)) }
        }
    }
}

@Composable
private fun TipsCard() {
    Card(
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(18.dp)) {
            Tip(R.drawable.ic_share, stringResource(R.string.tip_share_title), stringResource(R.string.tip_share))
            Tip(R.drawable.ic_keyboard, stringResource(R.string.tip_pc_title), stringResource(R.string.tip_pc))
            Tip(R.drawable.ic_arrow_down, stringResource(R.string.tip_receive_title), stringResource(R.string.tip_receive))
        }
    }
}

@Composable
private fun Tip(icon: Int, title: String, body: String) {
    Row(verticalAlignment = Alignment.Top) {
        IconTile(icon, size = 36.dp)
        Spacer(Modifier.width(14.dp))
        Column {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(2.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
