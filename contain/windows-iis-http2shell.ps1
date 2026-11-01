<#
.SYNOPSIS
    protection2shell :: HTTP2Shell containment for IIS (CVE-2026-111497)

.DESCRIPTION
    Refuses request bodies whose Content-Encoding contains "br" before IIS hands
    them to a FastCGI/PHP handler or an application that would decompress them.

    The guard is a URL Rewrite global rule (CustomResponse 415) written into the
    site's web.config. The original file is backed up next to it and -Remove
    restores a clean state by deleting exactly the marked rule.

.PARAMETER SitePath
    Physical path of the site root, e.g. C:\inetpub\wwwroot

.PARAMETER Remove
    Remove the guard again (undo).

.PARAMETER WhatIf
    Show what would change without writing anything.

.EXAMPLE
    .\windows-iis-http2shell.ps1 -SitePath C:\inetpub\wwwroot
    .\windows-iis-http2shell.ps1 -SitePath C:\inetpub\wwwroot -Remove

.NOTES
    Requires the IIS URL Rewrite module. Containment only — patch Node/PHP/.NET
    and libbrotli for the real fix. Test on a staging site first: any client
    that legitimately uploads Brotli-compressed bodies will be refused.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$SitePath,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$ruleName  = 'protection2shell deny brotli request bodies'
$stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$configPath = Join-Path $SitePath 'web.config'
$backupDir  = Join-Path $env:ProgramData 'protection2shell\backups'

function New-GuardRule {
    param([System.Xml.XmlDocument]$Doc)
    $rule = $Doc.CreateElement('rule')
    $rule.SetAttribute('name', $ruleName)
    $rule.SetAttribute('stopProcessing', 'true')

    $match = $Doc.CreateElement('match')
    $match.SetAttribute('url', '.*')
    [void]$rule.AppendChild($match)

    $conditions = $Doc.CreateElement('conditions')
    $cond = $Doc.CreateElement('add')
    $cond.SetAttribute('input', '{HTTP_CONTENT_ENCODING}')
    $cond.SetAttribute('pattern', '(^|,\s*)br(\s*(,|;|$))')
    $cond.SetAttribute('ignoreCase', 'true')
    [void]$conditions.AppendChild($cond)
    [void]$rule.AppendChild($conditions)

    $action = $Doc.CreateElement('action')
    $action.SetAttribute('type', 'CustomResponse')
    $action.SetAttribute('statusCode', '415')
    $action.SetAttribute('statusReason', 'Unsupported Media Type')
    $action.SetAttribute('statusDescription', 'Brotli request bodies are refused by protection2shell (CVE-2026-111497)')
    [void]$rule.AppendChild($action)

    return $rule
}

function Get-RulesNode {
    param([System.Xml.XmlDocument]$Doc, [switch]$Create)
    $xpath = "/*[local-name()='configuration']/*[local-name()='system.webServer']/*[local-name()='rewrite']/*[local-name()='rules']"
    $rules = $Doc.SelectSingleNode($xpath)
    if ($rules -or -not $Create) { return $rules }

    $server = $Doc.SelectSingleNode("/*[local-name()='configuration']/*[local-name()='system.webServer']")
    if (-not $server) {
        $server = $Doc.CreateElement('system.webServer')
        [void]$Doc.DocumentElement.AppendChild($server)
    }
    $rewrite = $Doc.CreateElement('rewrite')
    [void]$server.AppendChild($rewrite)
    $rules = $Doc.CreateElement('rules')
    [void]$rewrite.AppendChild($rules)
    return $rules
}

if (-not (Test-Path -LiteralPath $SitePath)) { throw "site path not found: $SitePath" }

if (Test-Path -LiteralPath $configPath) {
    $doc = New-Object System.Xml.XmlDocument
    $doc.PreserveWhitespace = $true
    $doc.Load($configPath)
} else {
    $doc = New-Object System.Xml.XmlDocument
    [void]$doc.AppendChild($doc.CreateXmlDeclaration('1.0', 'UTF-8', $null))
    $root = $doc.CreateElement('configuration')
    [void]$doc.AppendChild($root)
}

$rules = Get-RulesNode -Doc $doc -Create:(-not $Remove)
$existing = $null
if ($rules) {
    foreach ($node in $rules.SelectNodes("*[local-name()='rule']")) {
        if ($node.GetAttribute('name') -eq $ruleName) { $existing = $node }
    }
}

if ($Remove) {
    if (-not $existing) { Write-Host 'protection2shell: guard not present — nothing to remove.'; return }
    if ($PSCmdlet.ShouldProcess($configPath, 'remove HTTP2Shell guard')) {
        if (Test-Path -LiteralPath $configPath) {
            if (-not (Test-Path -LiteralPath $backupDir)) { [void](New-Item -ItemType Directory -Path $backupDir -Force) }
            Copy-Item -LiteralPath $configPath -Destination (Join-Path $backupDir "web.config.$stamp.bak") -Force
        }
        [void]$rules.RemoveChild($existing)
        $doc.Save($configPath)
        Write-Host "protection2shell: guard removed from $configPath (backup in $backupDir)"
    }
    return
}

if ($existing) { Write-Host 'protection2shell: guard already present — nothing to do.'; return }

if ($PSCmdlet.ShouldProcess($configPath, 'add HTTP2Shell guard')) {
    if (Test-Path -LiteralPath $configPath) {
        if (-not (Test-Path -LiteralPath $backupDir)) { [void](New-Item -ItemType Directory -Path $backupDir -Force) }
        Copy-Item -LiteralPath $configPath -Destination (Join-Path $backupDir "web.config.$stamp.bak") -Force
    }
    [void]$rules.AppendChild((New-GuardRule -Doc $doc))
    $doc.Save($configPath)
    Write-Host "protection2shell: guard installed for $SitePath"
    Write-Host '  legitimate Brotli-compressed request bodies are now refused with 415.'
    Write-Host '  this is containment: patch the runtime (Node 22.23.4+/24.22.1+/26.12.1+,'
    Write-Host '  brotli >= 1.2.1, .NET 8.0.33+/9.0.22+/10.0.14+) for the real fix.'
}
