# EdgeCat Automated Gateway Demonstration & Verification Script
# Copyright (c) 2026 Guo Qiang. Distributed under the terms of the Apache License 2.0.

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "          EdgeCat Local-First AI Gateway Test             " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$baseUrl = "http://localhost:8080"

# 1. Health check
Write-Host "`n[1/4] Testing Health Endpoint ($baseUrl/health)..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$baseUrl/health" -Method Get
    Write-Host "Status: $($health.status)" -ForegroundColor Green
    Write-Host "Local Tier Configured: $($health.local_tier.configured) (Active: $($health.local_tier.active_concurrency)/$($health.local_tier.max_concurrency))"
    Write-Host "Audit Logs Written: $($health.audit.written_total)"
} catch {
    Write-Host "Failed to connect to EdgeCat at $baseUrl. Make sure EdgeCat is running!" -ForegroundColor Red
    exit 1
}

# 2. Non-Streaming Request with PII (Phone & Email)
Write-Host "`n[2/4] Testing Non-Streaming Chat Completion with PII Masking..." -ForegroundColor Yellow
$payload = @{
    model = "gpt-4o-mini"
    messages = @(
        @{
            role = "user"
            content = "My phone is 13800138000 and my email is alice@corp.internal, please confirm."
        }
    )
    stream = $false
} | ConvertTo-Json

try {
    $resp = Invoke-RestMethod -Uri "$baseUrl/v1/chat/completions" -Method Post -Body $payload -ContentType "application/json"
    Write-Host "HTTP Status: 200 OK" -ForegroundColor Green
    Write-Host "Model Used: $($resp.model)"
    Write-Host "Assistant Reply: $($resp.choices[0].message.content)" -ForegroundColor Green
} catch {
    Write-Host "Request failed: $_" -ForegroundColor Red
}

# 3. Streaming Request (SSE)
Write-Host "`n[3/4] Testing Streaming SSE Chat Completion (stream=true)..." -ForegroundColor Yellow
$streamPayload = @{
    model = "default"
    messages = @(
        @{
            role = "user"
            content = "Stream test: my emergency number is 13912345678."
        }
    )
    stream = $true
} | ConvertTo-Json

try {
    $webReq = [System.Net.HttpWebRequest]::Create("$baseUrl/v1/chat/completions")
    $webReq.Method = "POST"
    $webReq.ContentType = "application/json"
    $reqBytes = [System.Text.Encoding]::UTF8.GetBytes($streamPayload)
    $webReq.ContentLength = $reqBytes.Length
    $stream = $webReq.GetRequestStream()
    $stream.Write($reqBytes, 0, $reqBytes.Length)
    $stream.Close()

    $webResp = $webReq.GetResponse()
    $reader = New-Object System.IO.StreamReader($webResp.GetResponseStream())
    Write-Host "Received Stream Chunks:" -ForegroundColor Green
    while (-not $reader.EndOfStream) {
        $line = $reader.ReadLine()
        if ($line -and $line.Trim()) {
            Write-Host "  $line" -ForegroundColor Gray
        }
    }
    $reader.Close()
    $webResp.Close()
} catch {
    Write-Host "Streaming failed: $_" -ForegroundColor Red
}

# 4. Check SQLite Audit Table
Write-Host "`n[4/4] Verifying SQLite Audit DB..." -ForegroundColor Yellow
Start-Sleep -Seconds 2 # Wait for async batch worker flush
try {
    $healthAfter = Invoke-RestMethod -Uri "$baseUrl/health" -Method Get
    Write-Host "Total Audit Records in DB: $($healthAfter.audit.written_total)" -ForegroundColor Green
    Write-Host "Dropped Records: $($healthAfter.audit.dropped_total)"
} catch {
    Write-Host "Audit check failed: $_" -ForegroundColor Red
}

Write-Host "`nAll verification steps completed!" -ForegroundColor Cyan
