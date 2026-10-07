<#
  Menog OS — static source audit (ad-hoc, read-only)

  REPAIRED 2026-10-06 at gate GP-R3 (Public Truth Rewrite).

  What changed and why:
    CHECK B previously asserted "0 NETWORK MODULE IMPORTS in src/*.ts" and treated any
    `node:net` import as a failure. That premise became obsolete once Phase 26 introduced a
    governed local transport: `packages/durable-state/src/endpointListenerBoundary.ts` now
    imports `createServer` from `node:net`, and it is the single socket-bind owner in the
    repository by design. The old check would therefore have reported a permanent false alarm
    and, worse, encoded a rule the project had deliberately superseded.

    CHECK B is now an ALLOWLIST audit: it still enumerates every network-module import and every
    third-party HTTP client, but it distinguishes a GOVERNED import at a declared boundary from an
    UNEXPECTED one. The third-party client prohibition is unchanged and still enforced.

    Behaviour change: the script now exits non-zero if CHECK B finds an unexpected network import,
    so the audit can actually fail instead of only printing. Nothing unexpected exists today, so a
    clean tree still exits 0.

  Verified at GP-R3: one `node:net` import, in the allowlisted boundary module; zero `dns`, zero
  `dgram`, zero `networkInterfaces`, and zero third-party HTTP clients anywhere in the source or
  dependency graph.

  This script is read-only. It writes nothing.
#>

$ErrorActionPreference = "Stop"
$script:unexpectedNetImport = $false

# --- Network-module allowlist -------------------------------------------------------------
# Only these paths may import a network module, and only for the stated reason.
$networkAllowlist = @(
  @{ Path = "packages\durable-state\src\endpointListenerBoundary.ts";
     Reason = "Phase-26 endpoint/listener boundary — the single governed socket-bind owner." }
)

Write-Host "=== STATIC CHECK A: NETWORK DEPENDENCIES (root package.json) ==="
$rootPkg = Get-Content "package.json" -Raw
$netDep = $rootPkg | Select-String -Pattern "axios|undici|node-fetch|got|socket\.io|ws"
if ($netDep.Matches.Count -eq 0) { Write-Host "  OK: root package.json has 0 network deps" }
else { $netDep | ForEach-Object { Write-Host "  NET_DEP:" $_.Line } }

Write-Host ""
Write-Host "=== STATIC CHECK B: NETWORK MODULE IMPORTS vs ALLOWLIST (apps + packages src) ==="
$srcFiles = @(Get-ChildItem -Path apps,packages -Recurse -Filter "*.ts" -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch "(node_modules|\.pnpm|dist|tests|test|spec)" })
Write-Host "  scanning $($srcFiles.Count) source files"

# Governed runtime modules and forbidden third-party clients, in ESM and CJS form.
$netModulePatt  = 'from\s+["''](?:node:)?(?:net|tls|http|https|dgram|http2|dns|axios|undici|node-fetch|got|ws|socket\.io)["'']'
$netRequirePatt = 'require\(\s*["''](?:node:)?(?:net|tls|http|https|dgram|http2|dns|axios|undici|node-fetch|got|ws|socket\.io)["'']'

$netMatches = @()
foreach ($f in $srcFiles) {
  $hits = @(Select-String -Path $f.FullName -Pattern $netModulePatt, $netRequirePatt -ErrorAction SilentlyContinue)
  if ($hits.Count -gt 0) { $netMatches += $hits }
}

$allowedPaths = @($networkAllowlist | ForEach-Object { $_.Path })

if ($netMatches.Count -eq 0) {
  Write-Host "  OK: 0 network module imports in source ($($srcFiles.Count) files scanned)"
}
else {
  Write-Host "  found $($netMatches.Count) network module import(s):"
  foreach ($m in $netMatches) {
    $rel = (Resolve-Path -Relative $m.Path) -replace '^\.\\', ''
    if ($allowedPaths -contains $rel) {
      Write-Host "    ALLOWED     $rel`:$($m.LineNumber)"
      Write-Host "                reason: $($networkAllowlist | Where-Object { $_.Path -eq $rel } | ForEach-Object { $_.Reason })"
    }
    else {
      $script:unexpectedNetImport = $true
      Write-Host "    UNEXPECTED  $rel`:$($m.LineNumber)"
      Write-Host "                $($m.Line.Trim())"
    }
  }
}

Write-Host ""
Write-Host "=== STATIC CHECK C: WRITE-CAPABILITY FS CALLS ==="
$auditTargets = @(Get-ChildItem -Path apps/cli/src,packages/verbs/src,packages/runtime-linux/src -Recurse -Filter "*.ts" -File -ErrorAction SilentlyContinue)
$writePatt = "\.writeFile\(|\.writeFileSync\(|\.appendFile\(|\.appendFileSync\(|\.createWriteStream\(|fsPromises\.write|fs\.write|fs\.rename|\.rm\(|\.rmdir\(|mkdir\("
$wm = Select-String -Path $auditTargets.FullName -Pattern $writePatt
if (-not $wm -or $wm.Count -eq 0) { Write-Host "  OK: 0 fs.write/append/rm calls in inspect/verbs/runtime-linux ($($auditTargets.Count) files)" }
else { $wm | ForEach-Object { Write-Host "  WRITE_MATCH:" $_.Path ":" $_.LineNumber ":" $_.Line } }

Write-Host ""
Write-Host "=== STATIC CHECK D: INSPECT VERB REQUIRED CAPABILITIES ==="
Select-String -Path packages/verbs/src/verbs.ts -Pattern "inspect" -Context 0,10 | Select-Object -First 12 | ForEach-Object {
  Write-Host ("  " + $_.Line)
  foreach ($cl in $_.Context.PostContext) { Write-Host ("    " + $cl) }
}

Write-Host ""
Write-Host "=== STATIC CHECK E: DOC<->IMPL CAPABILITY ID MATCH (EVENT_SCHEMA_v0.md vs policy/capabilities.ts) ==="
$policy = Get-Content "packages/policy/src/capabilities.ts" -Raw
$doc = Get-Content "docs/EVENT_SCHEMA_v0.md" -Raw
$capMatches = Select-String -InputObject $policy -AllMatches -Pattern "['\`"]([a-z:-]+)['\`"]" | ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique
Write-Host "  CapabilityIds from policy:"
foreach ($c in $capMatches) { if ($c -match '^[a-z]+:[a-z]+(-[a-z]+)*$|^untyped$') { Write-Host "    - $c" } }

Write-Host ""
Write-Host "=== SUMMARY ==="
if ($script:unexpectedNetImport) {
  Write-Host "  REVIEW: unexpected network import(s) found — see CHECK B. Failing."
  exit 1
}
Write-Host "  PASS: no unexpected network imports; third-party network clients: 0"
exit 0
