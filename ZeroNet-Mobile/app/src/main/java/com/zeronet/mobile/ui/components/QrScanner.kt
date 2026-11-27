package com.zeronet.mobile.ui.components

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.net.Uri
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.zeronet.mobile.R
import com.zeronet.mobile.ui.icons.ZeroIcons
import com.zeronet.mobile.ui.theme.ZeroTheme
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Reads a config or subscription QR code: live from the back camera, or from
 * a photo or screenshot (how most people receive them). Calls [onResult] once
 * with the decoded text.
 */
@Composable
fun QrScanner(onResult: (String) -> Unit, onCancel: () -> Unit, modifier: Modifier = Modifier) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val deliver by rememberUpdatedState(onResult)
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var cameraFailed by remember { mutableStateOf(false) }
    var notFound by remember { mutableStateOf(false) }
    var decoding by remember { mutableStateOf(false) }

    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
    LaunchedEffect(Unit) { if (!granted) permission.launch(Manifest.permission.CAMERA) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        decoding = true
        notFound = false
        scope.launch {
            val text = withContext(Dispatchers.Default) { runCatching { decodeQrImage(context, uri) }.getOrNull() }
            decoding = false
            if (text != null) deliver(text) else notFound = true
        }
    }

    Column(modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier
                .fillMaxWidth()
                .aspectRatio(1f)
                .clip(RoundedCornerShape(20.dp))
                .background(c.surfaceHi),
            contentAlignment = Alignment.Center,
        ) {
            if (granted && !cameraFailed) {
                CameraPreview(onDecoded = { deliver(it) }, onFailed = { cameraFailed = true })
                ViewFinder()
            } else {
                Text(
                    stringResource(R.string.scan_no_camera),
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.muted,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(24.dp),
                )
            }
        }
        Spacer(Modifier.height(10.dp))
        Text(
            stringResource(if (notFound) R.string.scan_not_found else R.string.scan_hint),
            style = MaterialTheme.typography.bodySmall,
            color = if (notFound) c.warn else c.muted,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TonalButton(stringResource(R.string.action_cancel), onCancel, Modifier.weight(1f), icon = ZeroIcons.Close)
            PrimaryButton(
                stringResource(R.string.scan_from_photo),
                { picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) },
                Modifier.weight(1f),
                icon = ZeroIcons.Qr,
                loading = decoding,
            )
        }
    }
}

@Composable
private fun CameraPreview(onDecoded: (String) -> Unit, onFailed: () -> Unit) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val decoded by rememberUpdatedState(onDecoded)
    val failed by rememberUpdatedState(onFailed)
    val view = remember {
        PreviewView(context).apply {
            scaleType = PreviewView.ScaleType.FILL_CENTER
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
    }
    AndroidView(factory = { view }, modifier = Modifier.fillMaxSize())
    DisposableEffect(owner) {
        val worker = Executors.newSingleThreadExecutor()
        val done = AtomicBoolean(false)
        var disposed = false
        var provider: ProcessCameraProvider? = null
        val main = ContextCompat.getMainExecutor(context)
        val future = ProcessCameraProvider.getInstance(context)
        future.addListener({
            if (disposed) return@addListener
            val p = runCatching { future.get() }.getOrNull() ?: run { failed(); return@addListener }
            provider = p
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(view.surfaceProvider) }
            // Config links make dense codes: 720p frames keep their modules readable.
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(
                    ResolutionSelector.Builder()
                        .setResolutionStrategy(ResolutionStrategy(Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER))
                        .build(),
                )
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(worker) { image ->
                try {
                    if (!done.get()) {
                        // The Y plane is a greyscale picture: all a QR reader needs.
                        val plane = image.planes[0]
                        val buffer = plane.buffer
                        val bytes = ByteArray(buffer.remaining()).also { buffer.get(it) }
                        val source = PlanarYUVLuminanceSource(bytes, plane.rowStride, image.height, 0, 0, image.width, image.height, false)
                        decodeQr(source, thorough = false)?.let { text ->
                            if (done.compareAndSet(false, true)) main.execute { if (!disposed) decoded(text) }
                        }
                    }
                } catch (_: Exception) {
                    // A malformed frame: wait for the next one.
                } finally {
                    image.close()
                }
            }
            runCatching {
                p.unbindAll()
                p.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            }.onFailure { failed() }
        }, main)
        onDispose {
            disposed = true
            provider?.unbindAll()
            worker.shutdown()
        }
    }
}

/** Corner marks showing where to hold the code. */
@Composable
private fun ViewFinder() {
    val accent = ZeroTheme.colors.accent
    Canvas(Modifier.fillMaxSize()) {
        val inset = size.minDimension * 0.16f
        val arm = size.minDimension * 0.12f
        val w = 4.dp.toPx()
        val l = inset; val t = inset; val r = size.width - inset; val b = size.height - inset
        listOf(
            Triple(Offset(l, t), Offset(arm, 0f), Offset(0f, arm)),
            Triple(Offset(r, t), Offset(-arm, 0f), Offset(0f, arm)),
            Triple(Offset(l, b), Offset(arm, 0f), Offset(0f, -arm)),
            Triple(Offset(r, b), Offset(-arm, 0f), Offset(0f, -arm)),
        ).forEach { (corner, h, v) ->
            drawLine(accent, corner, corner + h, w, StrokeCap.Round)
            drawLine(accent, corner, corner + v, w, StrokeCap.Round)
        }
    }
}

/** Decode a QR code in an image the user picked, downscaled to at most ~2000 px. */
private fun decodeQrImage(context: Context, uri: Uri): String? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    var sample = 1
    while (maxOf(bounds.outWidth, bounds.outHeight) / sample > 2048) sample *= 2
    val bitmap = context.contentResolver.openInputStream(uri)?.use {
        BitmapFactory.decodeStream(it, null, BitmapFactory.Options().apply { inSampleSize = sample })
    } ?: return null
    val pixels = IntArray(bitmap.width * bitmap.height)
    bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
    val source = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
    bitmap.recycle()
    return decodeQr(source, thorough = true)
}

/**
 * One frame, or one image. [thorough] also tries a second binarizer and the
 * inverted picture (light-on-dark codes), too slow for every camera frame.
 */
internal fun decodeQr(source: LuminanceSource, thorough: Boolean): String? {
    val reader = QRCodeReader()
    val hints = buildMap<DecodeHintType, Any> {
        put(DecodeHintType.CHARACTER_SET, "UTF-8")
        if (thorough) put(DecodeHintType.TRY_HARDER, true)
    }
    val sources = if (thorough) listOf(source, source.invert()) else listOf(source)
    for (s in sources) {
        val binarizers = if (thorough) listOf(HybridBinarizer(s), GlobalHistogramBinarizer(s)) else listOf(HybridBinarizer(s))
        for (bin in binarizers) {
            try {
                return reader.decode(BinaryBitmap(bin), hints).text
            } catch (_: ReaderException) {
                // Not found with this one; try the next.
            } finally {
                reader.reset()
            }
        }
    }
    return null
}
