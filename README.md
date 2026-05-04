# Azure Managed Identity Auditor

A CLI tool that audits Azure AI services to ensure they use managed identities instead of hardcoded credentials. Covers both live Azure resources and Infrastructure-as-Code files.

## Why this exists

Azure AI services can be accessed two ways: with **API keys** or with **managed identities**. Keys are dangerous — they can leak through logs, ARM exports, `git blame`, environment dumps, or misconfigured CI artifacts. A managed identity has no secret; it proves identity cryptographically via Azure AD tokens that are scoped, short-lived, and never touch your code or config.

This tool finds everywhere your Azure setup is still using keys.

## What it checks

### Live Azure resources

| Rule | Severity | Resource | Description |
|------|----------|----------|-------------|
| AI-001 | HIGH | Cognitive Services / Azure OpenAI | Local key authentication not disabled (`disableLocalAuth` ≠ true) |
| AI-002 | HIGH | Cognitive Services / Azure OpenAI | No managed identity assigned to the AI service |
| APP-001 | CRITICAL | App Service / Function App | App setting contains a hardcoded credential (by key name heuristic) |
| APP-002 | CRITICAL | App Service / Function App | App setting contains a connection string with an embedded account key |
| RBAC-001 | MEDIUM | Cognitive Services / Azure OpenAI | No managed identity holds a Cognitive Services data-plane role |
| FOUNDRY-001 | HIGH | AI Foundry Hub / Project workspace | Workspace has no managed identity — cannot authenticate to connected resources without storing keys |
| FOUNDRY-002 | HIGH | AI Foundry serverless API endpoint | Model deployment endpoint has `authMode: Key` |
| FOUNDRY-003 | HIGH | AI Foundry managed online endpoint | Real-time inference endpoint has `authMode: Key` instead of `AADToken` |
| FOUNDRY-004 | MEDIUM | AI Foundry workspace connection | Connection to OpenAI / AI Search / Storage uses `ApiKey`, `SAS`, or `PAT` instead of managed identity |

### IaC files (static analysis — no Azure login required)

Scans ARM templates (JSON), Bicep, Terraform / `.tfvars`, GitHub Actions and Azure Pipelines YAML, and `.env` files.

| Rule | Severity | What triggers it |
|------|----------|-----------------|
| IAC-001 | CRITICAL | ARM template has a raw credential value in a `name`/`value` pair or direct key field |
| IAC-002 | CRITICAL/HIGH | Bicep, Terraform, YAML, or `.env` file contains a credential pattern |

**Detected patterns:** Azure Storage connection strings with embedded account keys · Azure Service Bus / Event Hub connection strings · Azure SAS tokens · OpenAI-style `sk-` keys · Azure Cognitive Services 32-char hex keys · Generic `api_key = "..."` assignments · Azure SQL / database connection strings with passwords

**Safe-value filtering:** ARM `[parameters(...)]` and `[variables(...)]` expressions · Key Vault references (`@Microsoft.KeyVault(...)`) · Terraform `var.x` and `data.x` references · GitHub Actions `${{ secrets.X }}` expressions · Azure Pipelines `$(VARIABLE)` references · obvious placeholders (`PLACEHOLDER`, `<key>`, `your-api-key`, etc.)

## Installation

```bash
git clone https://github.com/linguaphile11/azure-identity-auditor
cd azure-identity-auditor
pip install -e .
```

For development (includes pytest, ruff, mypy):

```bash
pip install -e ".[dev]"
```

## Usage

### Scan IaC files (no Azure login required)

```bash
# Scan a directory recursively
aia scan-iac ./infra

# Scan multiple paths
aia scan-iac ./infra ./pipelines

# Output a self-contained HTML report
aia scan-iac ./infra --format html --output-dir ./reports

# Output JSON (useful for piping into other tools)
aia scan-iac ./infra --format json

# Only show CRITICAL and HIGH findings
aia scan-iac ./infra --min-severity HIGH
```

### Scan live Azure subscriptions

Requires an authenticated Azure session (`az login`, environment variables, or managed identity).

```bash
# Scan all accessible subscriptions
aia scan-azure

# Scan a specific subscription
aia scan-azure --subscription <subscription-id>

# Output all formats at once
aia scan-azure --format all --output-dir ./reports
```

### Full audit (Azure + IaC)

```bash
aia scan --iac-path ./infra
aia scan --subscription <id> --iac-path ./infra --format all --output-dir ./reports
aia scan --skip-azure --iac-path ./infra   # IaC only, no Azure credentials needed
```

### All CLI options

```
aia scan-iac [OPTIONS] PATHS...
aia scan-azure [OPTIONS]
aia scan [OPTIONS]

Common options:
  --format [console|json|html|all]   Output format (default: console)
  --output-dir / -o PATH             Write report files to this directory
  --min-severity LEVEL               Minimum severity to include (default: LOW)
  --fail-on LEVEL                    Exit 1 if findings at or above this level (default: CRITICAL)
                                     Use --fail-on never to always exit 0
  --subscription / -s ID             Subscription ID(s) to scan (scan-azure / scan)
  --iac-path / -p PATH               IaC path(s) to scan (scan)
  --skip-azure                       Skip live Azure scan (scan)
  --skip-iac                         Skip IaC file scan (scan)
```

## Output formats

**Console** — colored Rich table with severity badges, plus expandable finding details including description and exact remediation steps.

**JSON** — machine-readable report with summary counts, all finding fields, and scan metadata. Suitable for CI artifact storage or feeding into SIEM/ticketing integrations.

**HTML** — self-contained single-file report with severity filter buttons, full-text search, sortable columns, and expandable detail rows. No external dependencies.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above `--fail-on` threshold |
| 1 | One or more findings at or above threshold |

Use `--fail-on never` for reporting-only pipelines where you don't want to block CI.

## CI integration example

```yaml
# .github/workflows/audit.yml
- name: Audit IaC for hardcoded credentials
  run: |
    pip install azure-identity-auditor
    aia scan-iac ./infra --format all --output-dir ./audit-reports --fail-on HIGH

- name: Upload audit report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: identity-audit
    path: ./audit-reports/
```

## Authentication

The live Azure scanners use `DefaultAzureCredential`, which tries in order:

1. Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`)
2. Workload identity (in AKS)
3. Managed identity (on Azure VMs, App Service, etc.)
4. Azure CLI (`az login`)
5. Visual Studio Code / Azure PowerShell

## Required permissions

The scanning principal needs read-only access:

| Scanner | Required role |
|---------|--------------|
| AI services (AI-001, AI-002) | `Reader` on the subscription or resource group |
| App Services (APP-001, APP-002) | `Website Contributor` or `Reader` + list app settings |
| RBAC (RBAC-001) | `Reader` on the subscription |
| AI Foundry (FOUNDRY-001–004) | `Reader` on the subscription |

A subscription-level `Reader` role assignment covers all scanners.

## Development

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=azure_identity_auditor --cov-report=html

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

### Project structure

```
src/azure_identity_auditor/
├── cli.py                    # Click CLI entry point
├── models.py                 # Finding, ScanResult, Severity dataclasses
├── credentials/
│   └── patterns.py           # Compiled regex patterns for credential detection
├── scanners/
│   ├── ai_services.py        # AI-001, AI-002 (Cognitive Services / Azure OpenAI)
│   ├── app_services.py       # APP-001, APP-002 (App Service / Function Apps)
│   ├── rbac.py               # RBAC-001 (role assignments)
│   ├── ai_foundry.py         # FOUNDRY-001–004 (AI Foundry Hub/Project/endpoints)
│   └── iac.py                # IAC-001, IAC-002 (static IaC file analysis)
└── reporters/
    ├── console.py            # Rich console output
    ├── json_reporter.py      # JSON report
    └── html_reporter.py      # Self-contained HTML report
```

## Adding a new check

1. Add a `CredentialPattern` entry to `credentials/patterns.py` (for IaC patterns), or add a new check method to an existing scanner.
2. Choose a rule ID following the existing naming convention (`XX-NNN`).
3. Add a `Finding` with `rule_id`, `severity`, `description`, and `remediation`.
4. Add tests in `tests/`.
