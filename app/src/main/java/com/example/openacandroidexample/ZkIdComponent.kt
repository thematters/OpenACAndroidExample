package com.example.openacandroidexample

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel

@Composable
fun ZkIdComponent(vm: ProofViewModel = viewModel()) {
    LaunchedEffect(Unit) { vm.prepareResources() }

    val isBusy = vm.isDownloading || vm.isRunning
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // ── Title ────────────────────────────────────────────────
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text  = "OpenAC zkID",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text  = "CertChain RS4096 + UserSig RS2048 via MOICA",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }

        // ── Circuit Download ─────────────────────────────────────
        CircuitDownloadCard(vm = vm)

        // ── MOICA Section ────────────────────────────────────────
        AnimatedVisibility(visible = vm.circuitReady) {
            MoicaCard(vm = vm, isBusy = isBusy)
        }

        // ── Circuit Input JSON viewer ────────────────────────────
        AnimatedVisibility(visible = vm.inputJson != null) {
            InputJsonCard(json = vm.inputJson ?: "")
        }

        // ── ZK Pipeline ──────────────────────────────────────────
        AnimatedVisibility(visible = vm.circuitReady) {
            PipelineCard(vm = vm, isBusy = isBusy)
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit Download Card
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun CircuitDownloadCard(vm: ProofViewModel) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when {
                vm.downloadError != null -> MaterialTheme.colorScheme.errorContainer
                vm.circuitReady         -> MaterialTheme.colorScheme.secondaryContainer
                else                    -> MaterialTheme.colorScheme.surfaceVariant
            }
        ),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            val onColor = when {
                vm.downloadError != null -> MaterialTheme.colorScheme.onErrorContainer
                vm.circuitReady         -> MaterialTheme.colorScheme.onSecondaryContainer
                else                    -> MaterialTheme.colorScheme.onSurfaceVariant
            }
            Text(
                text = when {
                    vm.downloadError != null -> "Download failed"
                    vm.circuitReady         -> "Circuit + Keys ready"
                    vm.isDownloading        -> "Downloading…"
                    else                    -> "Circuit + Keys not downloaded"
                },
                style      = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                color      = onColor,
            )

            if (vm.downloadError != null) {
                Text(
                    text  = vm.downloadError!!,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }

            if (vm.isDownloading) {
                LinearProgressIndicator(
                    progress = { vm.downloadProgress.toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    text  = "${(vm.downloadProgress * 100).toInt()}%",
                    style = MaterialTheme.typography.bodySmall,
                    color = onColor,
                )
            }

            if (vm.circuitReady) {
                val dlSec = vm.downloadSeconds
                if (dlSec != null) {
                    Text(
                        text  = "Downloaded in %.1fs".format(dlSec),
                        style = MaterialTheme.typography.bodySmall,
                        color = onColor,
                    )
                } else {
                    Text(
                        text  = "cert_chain_rs4096 + user_sig_rs2048 + g3-smt",
                        style = MaterialTheme.typography.bodySmall,
                        color = onColor,
                    )
                }
            }

            if (!vm.circuitReady && !vm.isDownloading) {
                Button(
                    onClick  = { vm.downloadCircuit() },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Download Circuit + Keys") }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit Input JSON Card
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun InputJsonCard(json: String) {
    val clipboard         = LocalClipboardManager.current
    val hScroll           = rememberScrollState()
    var expanded by remember { mutableStateOf(false) }

    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier              = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment     = Alignment.CenterVertically,
            ) {
                Text(
                    "circuit_input.json",
                    style      = MaterialTheme.typography.labelLarge,
                    color      = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontWeight = FontWeight.SemiBold,
                )
                Row {
                    IconButton(onClick = { expanded = !expanded }) {
                        Icon(
                            imageVector        = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                            contentDescription = if (expanded) "Collapse" else "Expand",
                            tint               = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier           = Modifier.size(20.dp),
                        )
                    }
                    IconButton(onClick = { clipboard.setText(AnnotatedString(json)) }) {
                        Icon(
                            imageVector        = Icons.Filled.ContentCopy,
                            contentDescription = "Copy to clipboard",
                            tint               = MaterialTheme.colorScheme.primary,
                            modifier           = Modifier.size(20.dp),
                        )
                    }
                }
            }

            AnimatedVisibility(visible = expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    HorizontalDivider()
                    Text(
                        text       = json,
                        style      = MaterialTheme.typography.bodySmall,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        modifier   = Modifier.horizontalScroll(hScroll),
                    )
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MOICA Card
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun MoicaCard(vm: ProofViewModel, isBusy: Boolean) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                "MOICA Signature",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (vm.hasProofInput || vm.handoffStatus !is ProofViewModel.StepStatus.Idle) {
                Text(
                    text = "Matters handoff: ${vm.handoffSource ?: "openac://prove"}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            OutlinedTextField(
                value                = vm.idNum,
                onValueChange        = { vm.idNum = it },
                label                = { Text("ID Number") },
                singleLine           = true,
                modifier             = Modifier.fillMaxWidth(),
                keyboardOptions      = KeyboardOptions(capitalization = KeyboardCapitalization.Characters),
                visualTransformation = PasswordVisualTransformation(),
                enabled              = !isBusy,
            )

            StepButton(
                label   = "0. Get TBS Challenge",
                status  = vm.tbsStatus,
                enabled = !isBusy,
                testTag = "tbsChallengeButton",
                onClick = { vm.regenerateTBS() },
            )

            StepButton(
                label   = "1. Get SP Ticket",
                status  = vm.spTicketStatus,
                enabled = !isBusy && vm.tbsStatus.isSuccess,
                testTag = "fidoSpTicketButton",
                onClick = { vm.computeSPTicket() },
            )

            StepButton(
                label   = "2. Open MOICA App",
                status  = null,
                enabled = !isBusy && vm.spTicket != null,
                testTag = "fidoOpenMoicaButton",
                onClick = { vm.openMOICA() },
            )

            StepButton(
                label   = "3. Poll ATH Result",
                status  = vm.athResultStatus,
                enabled = !isBusy && vm.spTicket != null && !vm.hasProofInput,
                testTag = "fidoPollAthButton",
                onClick = { vm.pollAthResult() },
            )

            MoicaResults(vm = vm)
        }
    }
}

@Composable
private fun MoicaResults(vm: ProofViewModel) {
    val steps = listOf(
        "TBS Challenge" to vm.tbsStatus,
        "SP Ticket"     to vm.spTicketStatus,
        "ATH Result"    to vm.athResultStatus,
        "Handoff"       to vm.handoffStatus,
    )
    val hasAny = steps.any { (_, s) -> s !is ProofViewModel.StepStatus.Idle }
    AnimatedVisibility(visible = hasAny) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            HorizontalDivider()

            steps.forEach { (label, status) ->
                when (status) {
                    is ProofViewModel.StepStatus.Success ->
                        ResultRow(label, status.message, Color(0xFF2E7D32))
                    is ProofViewModel.StepStatus.Failure ->
                        ResultRow(label, status.message, MaterialTheme.colorScheme.error)
                    else -> {}
                }
            }

            vm.rtnVal?.let { rtnVal ->
                HorizontalDivider()
                ResultRow("rtn_val", rtnVal.ifEmpty { "(empty)" }, MaterialTheme.colorScheme.onSurface)
            }

            vm.athResponseString?.let { resp ->
                ResultRow(
                    "signed_response",
                    resp.take(64) + if (resp.length > 64) "…" else "",
                    MaterialTheme.colorScheme.onSurface,
                )
            }

            vm.athIssuerCert?.let { cert ->
                ResultRow(
                    "cert",
                    cert.take(64) + if (cert.length > 64) "…" else "",
                    MaterialTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ZK Pipeline Card
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun PipelineCard(vm: ProofViewModel, isBusy: Boolean) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                "ZK Pipeline",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            StepButton(
                label   = "4. Generate Input",
                status  = vm.generateInputStatus,
                enabled = !isBusy && vm.athResultStatus.isSuccess,
                testTag = "zkidGenerateInputButton",
                onClick = { vm.runGenerateInput() },
            )

            StepButton(
                label   = "5. Generate Proof",
                status  = vm.proveStatus,
                enabled = !isBusy,
                testTag = "zkidProveButton",
                onClick = { vm.runProve() },
            )

            StepButton(
                label   = "6. Verify Proof",
                status  = vm.verifyStatus,
                enabled = !isBusy && vm.proveStatus.isSuccess,
                testTag = "zkidVerifyButton",
                onClick = { vm.runVerify() },
            )

            HorizontalDivider()

            OutlinedButton(
                onClick  = { vm.runAll() },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("zkidRunAllButton"),
                enabled  = !isBusy,
            ) {
                if (vm.isRunning) {
                    CircularProgressIndicator(
                        modifier    = Modifier.size(16.dp),
                        strokeWidth = 2.dp,
                    )
                    Spacer(Modifier.width(8.dp))
                }
                Text("Run All (Prove → Verify)")
            }

            PipelineResults(vm = vm)
        }
    }
}

@Composable
private fun PipelineResults(vm: ProofViewModel) {
    val steps = listOf(
        "Generate Input" to vm.generateInputStatus,
        "Generate Proof" to vm.proveStatus,
        "Verify Proof"   to vm.verifyStatus,
    )
    val hasAny = steps.any { (_, s) -> s !is ProofViewModel.StepStatus.Idle }
    AnimatedVisibility(visible = hasAny) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            HorizontalDivider()
            steps.forEach { (label, status) ->
                when (status) {
                    is ProofViewModel.StepStatus.Success ->
                        ResultRow(label = label, value = status.message, color = Color(0xFF2E7D32))
                    is ProofViewModel.StepStatus.Failure ->
                        ResultRow(label = label, value = status.message, color = MaterialTheme.colorScheme.error)
                    else -> {}
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun StepButton(
    label:   String,
    status:  ProofViewModel.StepStatus?,
    enabled: Boolean,
    testTag: String,
    onClick: () -> Unit,
) {
    Row(
        modifier              = Modifier.fillMaxWidth(),
        verticalAlignment     = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Button(
            onClick  = onClick,
            modifier = Modifier
                .weight(1f)
                .testTag(testTag),
            enabled  = enabled,
        ) {
            if (status?.isRunning == true) {
                CircularProgressIndicator(
                    modifier    = Modifier.size(16.dp),
                    color       = MaterialTheme.colorScheme.onPrimary,
                    strokeWidth = 2.dp,
                )
                Spacer(Modifier.width(8.dp))
            }
            Text(label)
        }

        if (status != null && status !is ProofViewModel.StepStatus.Idle) {
            val badgeColor = when (status) {
                is ProofViewModel.StepStatus.Running -> MaterialTheme.colorScheme.secondary
                is ProofViewModel.StepStatus.Success -> Color(0xFF2E7D32)
                is ProofViewModel.StepStatus.Failure -> MaterialTheme.colorScheme.error
                else                                 -> MaterialTheme.colorScheme.secondary
            }
            val badgeLabel = when (status) {
                is ProofViewModel.StepStatus.Running -> "Running…"
                is ProofViewModel.StepStatus.Success -> "Done"
                is ProofViewModel.StepStatus.Failure -> "Failed"
                else                                 -> ""
            }
            Surface(
                shape = MaterialTheme.shapes.small,
                color = badgeColor.copy(alpha = 0.15f),
            ) {
                Text(
                    badgeLabel,
                    modifier   = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    style      = MaterialTheme.typography.labelSmall,
                    color      = badgeColor,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }
    }
}

@Composable
private fun ResultRow(label: String, value: String, color: Color) {
    Row(
        modifier              = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment     = Alignment.Top,
    ) {
        Text(
            label,
            style    = MaterialTheme.typography.bodySmall,
            color    = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.35f),
        )
        Text(
            value,
            style      = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
            color      = color,
            modifier   = Modifier.weight(0.65f),
        )
    }
}
