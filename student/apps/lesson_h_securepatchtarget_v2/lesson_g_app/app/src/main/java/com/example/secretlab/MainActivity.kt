package com.example.secretlab

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.SigningInfo
import android.location.Location
import android.location.LocationManager
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.foundation.Image
import coil.compose.rememberAsyncImagePainter
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.example.secretlab.secure.AppSecrets
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import androidx.compose.ui.text.input.ImeAction

private const val SUBMISSION_BASE_URL = "https://www.duszekjk.com/bsk/"
private const val TASK_1_PASSWORD = "harbor"
private const val TASK_1_CODE = "S2A9K1"
private const val TASK_1_ID = "G01"

data class PhotoEntry(val uri: Uri, val source: String)
data class SubmissionResult(val code: Int, val body: String)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                LessonGStarterApp()
            }
        }
    }
}

@Composable
private fun LessonGStarterApp() {
    val context = LocalContext.current
    val locationManager = remember { context.getSystemService(Context.LOCATION_SERVICE) as LocationManager }
    val scope = rememberCoroutineScope()
    val keyboardController = LocalSoftwareKeyboardController.current
    val focusManager = LocalFocusManager.current
    val photos = remember { mutableStateListOf<PhotoEntry>() }
    var studentId by remember { mutableStateOf("") }
    var banner by remember { mutableStateOf("Starter app: complete the task-specific security pieces.") }
    var currentLocation by remember { mutableStateOf<Location?>(null) }
    var currentPhotoCapture by remember { mutableStateOf<Uri?>(null) }
    var submittedTask1 by remember { mutableStateOf(false) }
    var submissionStatus by remember { mutableStateOf("Not submitted") }
    var viewerIndex by remember { mutableStateOf<Int?>(null) }
    var permissionsGranted by remember { mutableStateOf(false) }

    fun launchTask1Submit() {
        scope.launch {
            if (submittedTask1 || studentId.isBlank()) return@launch
            val locationOk = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
                ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
            val cameraOk = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
            val photosOk = ContextCompat.checkSelfPermission(context, Manifest.permission.READ_MEDIA_IMAGES) == PackageManager.PERMISSION_GRANTED ||
                ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
            if (!(locationOk && cameraOk && photosOk)) return@launch
            val result = submitTask1(studentId)
            submittedTask1 = result.success
            submissionStatus = result.statusLine
            banner = if (submittedTask1) "Task 1 completed and answer sent." else "Task 1 did not submit."
            keyboardController?.hide()
            focusManager.clearFocus(force = true)
        }
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions(),
    ) { granted ->
        val locationOk = granted[Manifest.permission.ACCESS_FINE_LOCATION] == true ||
            granted[Manifest.permission.ACCESS_COARSE_LOCATION] == true
        val cameraOk = granted[Manifest.permission.CAMERA] == true
        val photosOk = granted[Manifest.permission.READ_MEDIA_IMAGES] == true ||
            granted[Manifest.permission.READ_EXTERNAL_STORAGE] == true
        permissionsGranted = locationOk && cameraOk && photosOk
        banner = when {
            locationOk && cameraOk && photosOk -> "Permissions granted. Task 1 can submit automatically."
            !locationOk && !cameraOk && !photosOk -> "Location, camera, and photo permissions are still missing."
            !locationOk -> "Location permission is missing."
            !cameraOk -> "Camera permission is missing."
            else -> "Photo-library permission is missing."
        }
        if (permissionsGranted && studentId.isNotBlank() && !submittedTask1) {
            launchTask1Submit()
        }
    }

    val galleryLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia(),
    ) { uri ->
        if (uri != null) {
            photos += PhotoEntry(uri = uri, source = "Gallery")
            banner = "Added gallery photo."
        }
    }

    val cameraLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.TakePicture(),
    ) { ok ->
        val uri = currentPhotoCapture
        if (ok && uri != null) {
            photos += PhotoEntry(uri = uri, source = "Camera")
            banner = "Captured camera photo."
        } else if (!ok) {
            banner = "Camera capture canceled."
        }
        currentPhotoCapture = null
    }

    fun refreshLocation() {
        currentLocation = readBestLocation(locationManager)
    }

    LaunchedEffect(Unit) { refreshLocation() }

    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text("Mobile Security Lab", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(banner)

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Student / Task 1", style = MaterialTheme.typography.titleLarge)
                    OutlinedTextField(
                        value = studentId,
                        onValueChange = { studentId = it.trim() },
                        label = { Text("Student ID") },
                        modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                        keyboardActions = KeyboardActions(onDone = {
                            launchTask1Submit()
                        }),
                    )
                    Text("Submission status: $submissionStatus")
                    Text("Task 1 uses an app-embedded secret and submits when permissions and the student ID are both present.")
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Button(onClick = {
                            permissionLauncher.launch(
                                arrayOf(
                                    Manifest.permission.ACCESS_FINE_LOCATION,
                                    Manifest.permission.ACCESS_COARSE_LOCATION,
                                    Manifest.permission.CAMERA,
                                    Manifest.permission.READ_MEDIA_IMAGES,
                                    Manifest.permission.READ_EXTERNAL_STORAGE,
                                ),
                            )
                        }) {
                            Text("Request permissions")
                        }
                        Button(onClick = {
                            refreshLocation()
                            banner = "Location refreshed."
                        }) {
                            Text("Refresh location")
                        }
                    }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Small map", style = MaterialTheme.typography.titleLarge)
                    Text(locationSummary(currentLocation))
                    ApiMapCard(
                        location = currentLocation,
                        mapApiKey = AppSecrets.readMapApiKey(),
                    )
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Photo gallery", style = MaterialTheme.typography.titleLarge)
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Button(onClick = {
                            galleryLauncher.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                        }) {
                            Text("Add from gallery")
                        }
                        Button(onClick = {
                            val uri = createTempImageUri(context)
                            currentPhotoCapture = uri
                            cameraLauncher.launch(uri)
                        }) {
                            Text("Add from camera")
                        }
                    }
                    PhotoGrid(
                        photos = photos,
                        onOpenPhoto = { viewerIndex = it },
                    )
                }
            }

        }
    }

    if (viewerIndex != null && photos.isNotEmpty()) {
        FullScreenPhotoViewer(
            photos = photos,
            initialIndex = viewerIndex!!.coerceIn(0, photos.lastIndex),
            onDismiss = { viewerIndex = null },
        )
    }
}

@Composable
private fun ApiMapCard(
    location: Location?,
    mapApiKey: String?,
) {
    val lat = location?.latitude
    val lon = location?.longitude
    val hasLocation = lat != null && lon != null
    val mapUrl = if (hasLocation && !mapApiKey.isNullOrBlank()) {
        buildStaticMapUrl(lat = lat!!, lon = lon!!, apiKey = mapApiKey)
    } else {
        null
    }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .aspectRatio(1.2f)
            .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(16.dp)),
        tonalElevation = 1.dp,
    ) {
        Box(modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surfaceContainerLowest)) {
            if (mapUrl != null) {
                Image(
                    painter = rememberAsyncImagePainter(mapUrl),
                    contentDescription = "Current location map",
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.fillMaxSize(),
                )
                Box(
                    modifier = Modifier
                        .align(Alignment.Center)
                        .size(18.dp)
                        .background(Color.Transparent),
                ) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        drawCircle(Color(0xFFE4572E), radius = 14f, center = Offset(size.width / 2f, size.height / 2f))
                        drawCircle(Color.White, radius = 6f, center = Offset(size.width / 2f, size.height / 2f))
                    }
                }
            } else {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    val message = when {
                        !hasLocation -> "Grant location permission and refresh to load the map."
                        mapApiKey.isNullOrBlank() -> "Geoapify API key missing."
                        else -> "Map unavailable."
                    }
                    Text(
                        text = message,
                    )
                }
            }
        }
    }
}

private fun buildStaticMapUrl(lat: Double, lon: Double, apiKey: String): String {
    val zoom = 14
    val width = 640
    val height = 480
    return "https://maps.geoapify.com/v1/staticmap?style=osm-carto&width=$width&height=$height&center=lonlat:$lon,$lat&zoom=$zoom&marker=lonlat:$lon,$lat;type:circle;color:%23e4572e;size:48&apiKey=${apiKey.trim()}"
}

private fun locationSummary(location: Location?): String =
    if (location == null) {
        "No location fix yet. Grant location permission and refresh."
    } else {
        "Current location: ${"%.5f".format(location.latitude)}, ${"%.5f".format(location.longitude)}"
    }

private fun readBestLocation(locationManager: LocationManager): Location? {
    val providers = listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER, LocationManager.PASSIVE_PROVIDER)
    for (provider in providers) {
        runCatching { locationManager.getLastKnownLocation(provider) }
            .getOrNull()
            ?.let { return it }
    }
    return null
}

private fun createTempImageUri(context: Context): Uri {
    val dir = File(context.cacheDir, "captures").apply { mkdirs() }
    val file = File(dir, "capture-${UUID.randomUUID()}.jpg")
    return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
}

private fun prepareAnswer(vararg parts: String, limit: Int = 220): String {
    val finalAnswer = parts.joinToString("|")
    return finalAnswer.take(limit)
}

private data class SubmissionState(val success: Boolean, val statusLine: String)

private suspend fun submitTask1(studentId: String): SubmissionState = withContext(Dispatchers.IO) {
    val payload = TASK_1_CODE
    runCatching {
        val json = buildString {
            append("{")
            append("\"student_id\":\"").append(escapeJson(studentId)).append("\",")
            append("\"student_mail\":\"\",")
            append("\"task\":\"").append(escapeJson(TASK_1_ID)).append("\",")
            append("\"grupa\":\"\",")
            append("\"answer\":\"").append(escapeJson(payload)).append("\",")
            append("\"share_link\":\"\"")
            append("}")
        }
        val connection = URL("${SUBMISSION_BASE_URL}api/submit_answer/").openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.connectTimeout = 20_000
        connection.readTimeout = 20_000
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        connection.outputStream.use { it.write(json.toByteArray()) }
        val code = connection.responseCode
        val body = (connection.errorStream ?: connection.inputStream)?.bufferedReader()?.use { it.readText() }.orEmpty()
        connection.disconnect()
        SubmissionState(
            success = code in 200..299,
            statusLine = "Task 1 HTTP $code${if (body.isNotBlank()) " | $body" else ""}",
        )
    }.getOrElse { throwable ->
        SubmissionState(success = false, statusLine = "Task 1 error: ${throwable::class.simpleName}: ${throwable.message}")
    }
}

private suspend fun submitAnswer(taskId: String, studentId: String, answer: String): SubmissionState? = withContext(Dispatchers.IO) {
    runCatching {
        val payload = buildString {
            append("{")
            append("\"student_id\":\"").append(escapeJson(studentId)).append("\",")
            append("\"student_mail\":\"\",")
            append("\"task\":\"").append(escapeJson(taskId)).append("\",")
            append("\"grupa\":\"\",")
            append("\"answer\":\"").append(escapeJson(answer)).append("\",")
            append("\"share_link\":\"\"")
            append("}")
        }
        val connection = URL("${SUBMISSION_BASE_URL}api/submit_answer/").openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.connectTimeout = 20_000
        connection.readTimeout = 20_000
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        connection.outputStream.use { it.write(payload.toByteArray()) }
        val code = connection.responseCode
        val body = (connection.errorStream ?: connection.inputStream)?.bufferedReader()?.use { it.readText() }.orEmpty()
        connection.disconnect()
        SubmissionState(
            success = code in 200..299,
            statusLine = "Task $taskId HTTP $code${if (body.isNotBlank()) " | $body" else ""}",
        )
    }.getOrElse { throwable ->
        SubmissionState(success = false, statusLine = "Task $taskId error: ${throwable::class.simpleName}: ${throwable.message}")
    }
}

private fun escapeJson(text: String): String =
    text.replace("\\", "\\\\").replace("\"", "\\\"")

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun PhotoGrid(
    photos: List<PhotoEntry>,
    onOpenPhoto: (Int) -> Unit,
) {
    if (photos.isEmpty()) {
        Text("No photos yet.")
        return
    }

    LazyVerticalGrid(
        columns = GridCells.Adaptive(minSize = 128.dp),
        modifier = Modifier.fillMaxWidth().height(420.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        itemsIndexed(photos) { index, entry ->
            Card(onClick = { onOpenPhoto(index) }) {
                Column(modifier = Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .aspectRatio(1f)
                            .background(MaterialTheme.colorScheme.surfaceVariant),
                    ) {
                        Image(
                            painter = rememberAsyncImagePainter(entry.uri),
                            contentDescription = "Photo ${index + 1}",
                            modifier = Modifier.fillMaxSize(),
                            contentScale = ContentScale.Crop,
                        )
                    }
                    Text("Photo ${index + 1}", fontWeight = FontWeight.Bold)
                    Text(entry.source)
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun FullScreenPhotoViewer(
    photos: List<PhotoEntry>,
    initialIndex: Int,
    onDismiss: () -> Unit,
) {
    val pagerState = rememberPagerState(initialPage = initialIndex, pageCount = { photos.size })
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black),
        ) {
            HorizontalPager(
                state = pagerState,
                modifier = Modifier.fillMaxSize(),
            ) { page ->
                ZoomablePhoto(uri = photos[page].uri)
            }
            Button(
                onClick = onDismiss,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(16.dp),
            ) {
                Text("Close")
            }
        }
    }
}

@Composable
private fun ZoomablePhoto(uri: Uri) {
    var scale by remember { mutableStateOf(1f) }
    var offset by remember { mutableStateOf(Offset.Zero) }
    val painter = rememberAsyncImagePainter(uri)
    Box(
        modifier = Modifier
            .fillMaxSize()
            .clipToBounds()
            .background(Color.Black),
    ) {
        Image(
            painter = painter,
            contentDescription = "Full screen photo",
            contentScale = ContentScale.Fit,
            modifier = Modifier
                .fillMaxSize()
                .graphicsLayer {
                    scaleX = scale
                    scaleY = scale
                    translationX = offset.x
                    translationY = offset.y
                }
                .transformable(rememberTransformableState { zoomChange, panChange, _ ->
                    scale = (scale * zoomChange).coerceIn(1f, 4f)
                    offset += panChange
                }),
        )
    }
}
