package com.example.openacandroidexample

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.ZipInputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Throws(IOException::class)
fun copyFile(inputStream: InputStream, outputStream: OutputStream) {
    val buffer = ByteArray(1024)
    var read: Int
    while (inputStream.read(buffer).also { read = it } != -1) {
        outputStream.write(buffer, 0, read)
    }
}

@Composable
fun getFilePathFromAssets(name: String): String {
    val context = LocalContext.current
    return remember {
        val assetManager = context.assets
        val inputStream = assetManager.open(name)
        val file = File(context.filesDir, name)
        copyFile(inputStream, file.outputStream())
        file.absolutePath
    }
}

suspend fun downloadAndUnzipToFilesDir(context: Context, zipUrl: String, targetFileName: String): String =
    withContext(Dispatchers.IO) {
        val outputFile = File(context.filesDir, targetFileName)
        if (!outputFile.exists()) {
            val connection = URL(zipUrl).openConnection() as HttpURLConnection
            try {
                connection.connect()
                ZipInputStream(connection.inputStream).use { zip ->
                    var entry = zip.nextEntry
                    while (entry != null) {
                        if (!entry.isDirectory && entry.name == targetFileName) {
                            outputFile.outputStream().use { out -> zip.copyTo(out) }
                            break
                        }
                        entry = zip.nextEntry
                    }
                }
            } finally {
                connection.disconnect()
            }
        }
        outputFile.absolutePath
    }

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val vm: ProofViewModel = viewModel()

            // Handle cold-start: app launched directly by the MOICA callback URL.
            LaunchedEffect(Unit) {
                intent?.data?.let { vm.handleOpenUri(it) }
            }

            // Handle warm-start: activity already running (singleTop) when MOICA redirects back.
            DisposableEffect(vm) {
                val listener = { newIntent: Intent ->
                    newIntent.data?.let { vm.handleOpenUri(it) }
                    Unit
                }
                addOnNewIntentListener(listener)
                onDispose { removeOnNewIntentListener(listener) }
            }

            MainScreen(vm = vm)
        }
    }
}

@Composable
fun MainScreen(vm: ProofViewModel = viewModel()) {
    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("zkID")

    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Column(modifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)
        ) {
            TabRow(selectedTabIndex = selectedTab) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        text = { Text(title) },
                        selected = selectedTab == index,
                        onClick = { selectedTab = index }
                    )
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
            when (selectedTab) {
                else -> ZkIdComponent(vm = vm)
            }
        }
    }
}
