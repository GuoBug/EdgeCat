# EdgeCat Evaluation & Benchmark Script (supports Roadmap R3.3)
# Runs reproducible probes against a running EdgeCat + mock_upstream (or live Ollama)
# and reports placeholder fidelity, fallback breakdown, and estimated token savings.

param(
    [string]$BaseUrl = "http://127.0.0.1:8080",
    [string]$Token = "",
    [int]$Iterations = 10
)

$ErrorActionPreference = "Stop"

$headers = @{ "Content-Type" = "application/json" }
if ($Token -ne "") {
    $headers["Authorization"] = "Bearer $Token"
}

$localHits = 0
$cloudFallbacks = 0
$errors = 0
$piiRestored = 0
$piiTested = 0
$totalPromptTokens = 0
$totalCompletionTokens = 0

Write-Host "=== EdgeCat Evaluation ($Iterations iterations) ===" -ForegroundColor Cyan

for ($i = 1; $i -le $Iterations; $i++) {
    $phone = "13800138000"
    $body = @{
        model    = "default"
        stream   = $false
        messages = @(
            @{ role = "user"; content = "Repeat this phone number verbatim: $phone" }
        )
    } | ConvertTo-Json -Depth 5

    try {
        $resp = Invoke-WebRequest -Uri "$BaseUrl/v1/chat/completions" -Method Post -Headers $headers -Body $body -UseBasicParsing
        $route = $resp.Headers["X-EdgeCat-Route"]
        if ($route -eq "local") { $localHits++ } else { $cloudFallbacks++ }

        $json = $resp.Content | ConvertFrom-Json
        $piiTested++
        $reply = $json.choices[0].message.content
        if ($reply -match $phone -and $reply -notmatch "\{\{EC_PII_") {
            $piiRestored++
        }
        if ($json.usage) {
            $totalPromptTokens += [int]$json.usage.prompt_tokens
            $totalCompletionTokens += [int]$json.usage.completion_tokens
        }
    }
    catch {
        $errors++
        Write-Warning "Iteration $i failed: $_"
    }
}

$localRate = if ($Iterations -gt 0) { [math]::Round(($localHits / $Iterations) * 100, 1) } else { 0 }
$fidelityRate = if ($piiTested -gt 0) { [math]::Round(($piiRestored / $piiTested) * 100, 1) } else { 0 }

Write-Host ""
Write-Host "--- Summary ---" -ForegroundColor Green
Write-Host "Local Hits         : $localHits / $Iterations ($localRate%)"
Write-Host "Cloud Fallbacks    : $cloudFallbacks"
Write-Host "Errors             : $errors"
Write-Host "PII Fidelity Rate  : $piiRestored / $piiTested ($fidelityRate%)"
Write-Host "Local Tokens Saved : prompt=$totalPromptTokens, completion=$totalCompletionTokens"

try {
    $admin = Invoke-RestMethod -Uri "$BaseUrl/admin/status" -Headers $headers -Method Get
    Write-Host "Breaker State      : $($admin.local_tier.circuit_breaker.state) (failures=$($admin.local_tier.circuit_breaker.consecutive_failures))"
    Write-Host "Total Fallbacks    : $($admin.local_tier.fallbacks_total)"
}
catch {
    Write-Host "(/admin/status unavailable or requires auth token)" -ForegroundColor Yellow
}
