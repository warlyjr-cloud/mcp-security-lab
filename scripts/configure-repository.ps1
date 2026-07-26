param(
  [string]$Repository = "warlyjr-cloud/mcp-security-lab",
  [string]$GitHubCliPath,
  [switch]$Apply
)

$ErrorActionPreference = "Stop"

if (-not $GitHubCliPath) {
  $command = Get-Command gh -ErrorAction SilentlyContinue
  if ($command) {
    $GitHubCliPath = $command.Source
  } else {
    $defaultPath = Join-Path $env:ProgramFiles "GitHub CLI\gh.exe"
    if (Test-Path -LiteralPath $defaultPath) {
      $GitHubCliPath = $defaultPath
    }
  }
}

$settings = @{
  has_issues = $true
  delete_branch_on_merge = $true
  allow_squash_merge = $true
  allow_merge_commit = $false
  allow_rebase_merge = $false
}

$protection = @{
  required_status_checks = @{
    strict = $true
    contexts = @(
      "Node 22 / Linux",
      "Node 24 / Linux",
      "Node 26 / Linux",
      "Coverage, benchmark, audit, and package",
      "JavaScript and TypeScript"
    )
  }
  enforce_admins = $true
  required_pull_request_reviews = @{
    dismiss_stale_reviews = $true
    require_code_owner_reviews = $true
    required_approving_review_count = 1
  }
  restrictions = $null
  required_linear_history = $true
  allow_force_pushes = $false
  allow_deletions = $false
  block_creations = $false
  required_conversation_resolution = $true
  lock_branch = $false
  allow_fork_syncing = $true
}

Write-Host "Repository: $Repository"
Write-Host "Mode: $(if ($Apply) { 'APPLY' } else { 'DRY RUN' })"
Write-Host "PATCH /repos/$Repository"
$settings | ConvertTo-Json -Depth 10
Write-Host "PUT /repos/$Repository/branches/main/protection"
$protection | ConvertTo-Json -Depth 10
Write-Host "PUT /repos/$Repository/vulnerability-alerts"
Write-Host "PUT /repos/$Repository/automated-security-fixes"

if (-not $Apply) {
  Write-Host "No changes made. Rerun with -Apply after reviewing the output."
  exit 0
}

if (-not $GitHubCliPath -or -not (Test-Path -LiteralPath $GitHubCliPath)) {
  throw "GitHub CLI was not found. Install gh or pass -GitHubCliPath."
}

& $GitHubCliPath auth status
if ($LASTEXITCODE -ne 0) {
  throw "GitHub CLI authentication is required."
}

$settings | ConvertTo-Json -Depth 10 -Compress |
  & $GitHubCliPath api --method PATCH "repos/$Repository" --input -
if ($LASTEXITCODE -ne 0) {
  throw "Failed to update repository settings."
}

$protection | ConvertTo-Json -Depth 10 -Compress |
  & $GitHubCliPath api --method PUT "repos/$Repository/branches/main/protection" --input -
if ($LASTEXITCODE -ne 0) {
  throw "Failed to update branch protection."
}

& $GitHubCliPath api --method PUT "repos/$Repository/vulnerability-alerts"
if ($LASTEXITCODE -ne 0) {
  throw "Failed to enable vulnerability alerts."
}

& $GitHubCliPath api --method PUT "repos/$Repository/automated-security-fixes"
if ($LASTEXITCODE -ne 0) {
  throw "Failed to enable automated security fixes."
}

Write-Host "Repository security settings applied."
