<#
    Reporting.ps1 - Console summary plus a self-contained HTML report.
#>

function Write-HardeningSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Result,
        [Parameter(Mandatory)][string]$Mode
    )

    $summary = Get-HardeningSummary -Result $Result

    Write-Host ''
    Write-HardeningBanner -Title "$Mode summary" -Subtitle "$($summary.ScorePercent)% of selected controls are in the hardened state"

    $rows = [ordered]@{
        'Controls evaluated'   = $summary.Total
        'Already compliant'    = $summary.Compliant
        'Remediated this run'  = $summary.Remediated
        'Still drifted'        = $summary.Drift
        'Needs manual action'  = $summary.Manual
        'Pending reboot'       = $summary.PendingReboot
        'Failed'               = $summary.Failed
    }

    foreach ($key in $rows.Keys) {
        $level = switch ($key) {
            'Still drifted' { if ($rows[$key] -gt 0) { 'Warn' } else { 'Good' } }
            'Needs manual action' { if ($rows[$key] -gt 0) { 'Warn' } else { 'Good' } }
            'Failed' { if ($rows[$key] -gt 0) { 'Bad' } else { 'Good' } }
            default { 'Info' }
        }
        Write-HardeningLog ("{0,-22} {1}" -f $key, $rows[$key]) $level
    }

    $outstanding = @($Result | Where-Object { $_.Status -in @('Drift', 'Manual', 'Failed', 'Error') })
    if ($outstanding.Count -gt 0) {
        Write-Host ''
        Write-HardeningLog 'Outstanding items' 'Step'
        foreach ($item in $outstanding) {
            Write-HardeningLog ("{0}  {1}" -f $item.Id, $item.Name) 'Warn'
            Write-HardeningLog $item.Detail 'Detail'
        }
    }

    if ($summary.NeedsReboot) {
        $pending = @($Result | Where-Object { $_.RequiresReboot -and $_.Changed })
        Write-Host ''
        Write-HardeningLog 'A restart is needed before these changes take effect:' 'Warn'
        foreach ($p in $pending) { Write-HardeningLog "$($p.Id)  $($p.Name)" 'Detail' }
    }
}

function Write-SweepSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $order = @('Critical', 'High', 'Medium', 'Low', 'Info')
    $actionable = @($Finding | Where-Object { $_.Severity -ne 'Info' })

    Write-Host ''
    Write-HardeningBanner -Title 'Threat sweep summary' -Subtitle "$($actionable.Count) actionable finding(s), $(@($Finding).Count) total"

    if (@($Finding).Count -eq 0) {
        Write-HardeningLog 'Nothing found. No evidence of scanning, poisoning or remote-execution tooling in the window examined.' 'Good'
        return
    }

    foreach ($sev in $order) {
        $group = @($Finding | Where-Object Severity -EQ $sev)
        if ($group.Count -eq 0) { continue }

        $level = switch ($sev) {
            'Critical' { 'Bad' }
            'High' { 'Bad' }
            'Medium' { 'Warn' }
            'Low' { 'Warn' }
            default { 'Info' }
        }

        Write-Host ''
        Write-HardeningLog "$sev ($($group.Count))" $level
        foreach ($f in $group) {
            Write-HardeningLog "$($f.Id)  $($f.Title)" $level
            Write-HardeningLog $f.Detail 'Detail'
            if ($f.Recommendation) { Write-HardeningLog "-> $($f.Recommendation)" 'Detail' }
        }
    }
}

function Export-HardeningReport {
    <#
        .SYNOPSIS
        Writes a single self-contained HTML file describing the run.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Mode,
        [AllowEmptyCollection()][object[]]$Result = @(),
        [AllowEmptyCollection()][object[]]$Finding = @(),
        [pscustomobject]$Facts
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write HTML report')) { return }

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }

    $summary = Get-HardeningSummary -Result $Result
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')

    $statusClass = @{
        Compliant     = 'ok'
        Remediated    = 'ok'
        Drift         = 'warn'
        Manual        = 'warn'
        PendingReboot = 'warn'
        WhatIf        = 'info'
        Failed        = 'bad'
        Error         = 'bad'
    }

    $sevClass = @{ Critical = 'bad'; High = 'bad'; Medium = 'warn'; Low = 'warn'; Info = 'info' }

    $controlRows = foreach ($r in ($Result | Sort-Object Category, Id)) {
        $cls = if ($statusClass.ContainsKey($r.Status)) { $statusClass[$r.Status] } else { 'info' }
        @"
      <tr>
        <td class="mono">$(ConvertTo-HtmlText $r.Id)</td>
        <td><div class="name">$(ConvertTo-HtmlText $r.Name)</div><div class="muted">$(ConvertTo-HtmlText $r.Rationale)</div></td>
        <td>$(ConvertTo-HtmlText $r.Category)</td>
        <td>$(ConvertTo-HtmlText $r.Tier)</td>
        <td><span class="chip $cls">$(ConvertTo-HtmlText $r.Status)</span></td>
        <td class="muted">$(ConvertTo-HtmlText $r.Detail)</td>
        <td class="muted">$(ConvertTo-HtmlText (@($r.Counters) -join ', '))</td>
      </tr>
"@
    }

    $findingCards = foreach ($f in ($Finding | Sort-Object { @('Critical', 'High', 'Medium', 'Low', 'Info').IndexOf($_.Severity) })) {
        $cls = if ($sevClass.ContainsKey($f.Severity)) { $sevClass[$f.Severity] } else { 'info' }
        @"
      <article class="finding $cls">
        <header><span class="chip $cls">$(ConvertTo-HtmlText $f.Severity)</span> <strong>$(ConvertTo-HtmlText $f.Title)</strong> <span class="mono muted">$(ConvertTo-HtmlText $f.Id)</span></header>
        <p>$(ConvertTo-HtmlText $f.Detail)</p>
        $(if ($f.Recommendation) { "<p class=""rec"">$(ConvertTo-HtmlText $f.Recommendation)</p>" })
      </article>
"@
    }

    $findingSection = if (@($Finding).Count -gt 0) {
        @"
    <h2>Threat sweep findings</h2>
    <section class="findings">
$($findingCards -join "`n")
    </section>
"@
    } else { '' }

    $controlSection = if (@($Result).Count -gt 0) {
        @"
    <h2>Controls</h2>
    <table>
      <colgroup>
        <col class="c-id"><col class="c-name"><col class="c-cat"><col class="c-tier">
        <col class="c-status"><col class="c-detail"><col class="c-counters">
      </colgroup>
      <thead><tr><th>ID</th><th>Control</th><th>Category</th><th>Tier</th><th>Status</th><th>Detail</th><th>Counters</th></tr></thead>
      <tbody>
$($controlRows -join "`n")
      </tbody>
    </table>
"@
    } else { '' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kali countermeasures - $(ConvertTo-HtmlText $Mode) report</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 2rem 1.25rem 4rem; background: #0b0e14; color: #d6deeb;
         font: 15px/1.6 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif; }
  .wrap { max-width: 1180px; margin: 0 auto; }
  h1 { font-size: 1.6rem; margin: 0 0 .25rem; color: #fff; }
  h2 { font-size: 1.15rem; margin: 2.5rem 0 .75rem; color: #fff; }
  .sub { color: #7d8aa3; margin: 0 0 2rem; }
  .cards { display: grid; gap: .75rem; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
  .card { background: #131722; border: 1px solid #1e2533; border-radius: 10px; padding: 1rem; }
  .card .n { font-size: 1.75rem; font-weight: 650; color: #fff; }
  .card .l { color: #7d8aa3; font-size: .82rem; text-transform: uppercase; letter-spacing: .04em; }
  table { width: 100%; border-collapse: collapse; background: #131722;
          border: 1px solid #1e2533; border-radius: 10px; overflow: hidden; }
  th, td { text-align: left; padding: .7rem .85rem; border-bottom: 1px solid #1e2533; vertical-align: top; }
  th { background: #171c28; color: #9fb0c9; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
  tr:last-child td { border-bottom: 0; }
  table { table-layout: fixed; }
  col.c-id { width: 80px; }
  col.c-name { width: 30%; }
  col.c-cat { width: 122px; }
  col.c-tier { width: 92px; }
  col.c-status { width: 106px; }
  col.c-detail { width: 19%; }
  col.c-counters { width: 17%; }
  td.mono { white-space: nowrap; }
  td.muted { overflow-wrap: anywhere; }
  .name { color: #fff; font-weight: 550; }
  .muted { color: #7d8aa3; font-size: .86rem; }
  .mono { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; font-size: .85rem; }
  .chip { display: inline-block; padding: .12rem .55rem; border-radius: 999px;
          font-size: .78rem; font-weight: 600; white-space: nowrap; }
  .chip.ok   { background: #10351f; color: #6ee7a0; }
  .chip.warn { background: #3a2f10; color: #f3c969; }
  .chip.bad  { background: #3c1618; color: #ff8b8b; }
  .chip.info { background: #16293c; color: #7cc5f5; }
  .findings { display: grid; gap: .75rem; }
  .finding { background: #131722; border: 1px solid #1e2533; border-left-width: 3px; border-radius: 10px; padding: 1rem 1.15rem; }
  .finding.bad  { border-left-color: #ff6b6b; }
  .finding.warn { border-left-color: #e2b23c; }
  .finding.info { border-left-color: #4a9fe0; }
  .finding p { margin: .6rem 0 0; }
  .finding .rec { color: #9fb0c9; border-left: 2px solid #2a3344; padding-left: .75rem; }
  footer { margin-top: 3rem; color: #5b6880; font-size: .82rem; }
  @media (max-width: 760px) { body { padding: 1rem .75rem 3rem; }
    table, thead, tbody, th, td, tr, colgroup, col { display: block; width: auto; }
    thead, colgroup { display: none; } td { border: 0; padding: .3rem .85rem; }
    tr { border-bottom: 1px solid #1e2533; padding: .6rem 0; } }
</style>
</head>
<body>
<div class="wrap">
  <h1>Windows 11 countermeasure report</h1>
  <p class="sub">$(ConvertTo-HtmlText $Mode) run on <strong>$(ConvertTo-HtmlText $Facts.ComputerName)</strong> &mdash; $(ConvertTo-HtmlText $Facts.OSCaption) build $(ConvertTo-HtmlText $Facts.OSBuild) &mdash; generated $generated</p>

  <div class="cards">
    <div class="card"><div class="n">$($summary.ScorePercent)%</div><div class="l">Hardened</div></div>
    <div class="card"><div class="n">$($summary.Total)</div><div class="l">Controls</div></div>
    <div class="card"><div class="n">$($summary.Compliant + $summary.Remediated)</div><div class="l">In desired state</div></div>
    <div class="card"><div class="n">$($summary.Drift + $summary.Manual)</div><div class="l">Outstanding</div></div>
    <div class="card"><div class="n">$(@($Finding | Where-Object { $_.Severity -ne 'Info' }).Count)</div><div class="l">Sweep findings</div></div>
  </div>

$findingSection
$controlSection

  <footer>
    Generated by Invoke-KaliCountermeasures. BitLocker and other volume-encryption settings are
    deliberately out of scope and were not read or modified.
  </footer>
</div>
</body>
</html>
"@

    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
    Write-HardeningLog "HTML report written to $Path" 'Good'
}

function ConvertTo-HtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory, ValueFromPipeline)][AllowNull()][AllowEmptyString()]$Text)

    process {
        if ($null -eq $Text) { return '' }
        [System.Net.WebUtility]::HtmlEncode([string]$Text)
    }
}

function Export-HardeningJson {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Mode,
        [AllowEmptyCollection()][object[]]$Result = @(),
        [AllowEmptyCollection()][object[]]$Finding = @(),
        [pscustomobject]$Facts
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write JSON report')) { return }

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }

    [ordered]@{
        Mode        = $Mode
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Host        = $Facts
        Summary     = Get-HardeningSummary -Result $Result
        Controls    = @($Result | Select-Object Id, Name, Category, Tier, Status, Detail, Changed, RequiresReboot, AuditOnly, Counters, Impact)
        Findings    = @($Finding)
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8

    Write-HardeningLog "JSON report written to $Path" 'Good'
}
