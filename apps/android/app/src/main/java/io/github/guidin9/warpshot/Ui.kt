package io.github.guidin9.warpshot

import android.os.Build
import androidx.annotation.DrawableRes
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** The PC icon's gradient (apps/windows-ui/src-tauri/icons). */
private val MarkStart = Color(0xFF0563BB)
private val MarkEnd = Color(0xFF3793DC)

// Before Android 12 there are no wallpaper colors: a blue scheme near the logo.
private val LightFallback = lightColorScheme(
    primary = Color(0xFF005FB8),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD6E3FF),
    onPrimaryContainer = Color(0xFF001B3E),
    secondaryContainer = Color(0xFFDAE2F9),
    onSecondaryContainer = Color(0xFF131C2B),
)
private val DarkFallback = darkColorScheme(
    primary = Color(0xFFA9C7FF),
    onPrimary = Color(0xFF003063),
    primaryContainer = Color(0xFF00468C),
    onPrimaryContainer = Color(0xFFD6E3FF),
    secondaryContainer = Color(0xFF3E4759),
    onSecondaryContainer = Color(0xFFDAE2F9),
)

/** Material 3 with the wallpaper's colors (Android 12+), like the system's own apps. */
@Composable
fun WarpTheme(content: @Composable () -> Unit) {
    val ctx = LocalContext.current
    val dark = isSystemInDarkTheme()
    val scheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> DarkFallback
        else -> LightFallback
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

/** The app icon drawn in the UI: the arrow on the PC icon's gradient. */
@Composable
fun AppMark(size: Dp, modifier: Modifier = Modifier) {
    Box(
        modifier
            .size(size)
            .clip(RoundedCornerShape(size * 0.28f))
            .background(Brush.linearGradient(listOf(MarkStart, MarkEnd))),
    ) {
        Icon(
            painterResource(R.drawable.ic_arrow_mark),
            contentDescription = null,
            tint = Color.White,
            modifier = Modifier.fillMaxSize(),
        )
    }
}

/** An icon on a tinted rounded square, used to lead list rows and cards. */
@Composable
fun IconTile(
    @DrawableRes icon: Int,
    modifier: Modifier = Modifier,
    size: Dp = 48.dp,
    container: Color = MaterialTheme.colorScheme.secondaryContainer,
    tint: Color = MaterialTheme.colorScheme.onSecondaryContainer,
) {
    Box(
        modifier.size(size).clip(RoundedCornerShape(size * 0.3f)).background(container),
        contentAlignment = Alignment.Center,
    ) {
        Icon(painterResource(icon), contentDescription = null, tint = tint, modifier = Modifier.size(size * 0.5f))
    }
}

/** "Sending x to PC" / "Receiving from PC" for a transfer. */
@Composable
fun transferTitle(t: TransferState): String = when {
    t.incoming -> stringResource(R.string.receiving_from, t.peer)
    t.label.isEmpty() -> stringResource(R.string.sending_to, t.peer)
    else -> stringResource(R.string.sending_item_to, t.label, t.peer)
}

/** One running transfer: direction, name, progress and Cancel. */
@Composable
fun TransferRow(t: TransferState, onCancel: () -> Unit, modifier: Modifier = Modifier) {
    val ctx = LocalContext.current
    Row(modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        IconTile(if (t.incoming) R.drawable.ic_arrow_down else R.drawable.ic_arrow_up, size = 40.dp)
        Column(
            Modifier.weight(1f).padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                transferTitle(t),
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            TransferProgress(t)
            Text(
                progressLine(ctx, t),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IconButton(onClick = onCancel) {
            Icon(painterResource(R.drawable.ic_close), contentDescription = stringResource(R.string.cancel))
        }
    }
}

/** A determinate bar once data flows, an indeterminate one while connecting. */
@Composable
fun TransferProgress(t: TransferState, modifier: Modifier = Modifier) {
    if (t.running && t.total > 0) {
        LinearProgressIndicator(progress = { t.fraction }, modifier = modifier.fillMaxWidth())
    } else {
        LinearProgressIndicator(modifier.fillMaxWidth())
    }
}
