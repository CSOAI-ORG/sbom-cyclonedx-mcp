# SBOM CycloneDX + SPDX Generator/Validator MCP

[![PyPI](https://img.shields.io/pypi/v/sbom-cyclonedx-mcp)](https://pypi.org/project/sbom-cyclonedx-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-governance--mcp-purple)](https://meok.ai)

Software Bill of Materials generation + validation in CycloneDX 1.6 and SPDX 2.3 formats. Required by EO 14028 + NIS2 + CRA.

## Install

```bash
pip install sbom-cyclonedx-mcp
```

## Tools

| Tool | Purpose |
|------|---------|
| `generate_sbom_cyclonedx` | Generate CycloneDX 1.6 SBOM from package manifests |
| `generate_sbom_spdx` | Generate SPDX 2.3 SBOM |
| `validate_sbom` | Validate SBOM against CycloneDX/SPDX schema + completeness |
| `vex_attach` | Attach VEX (Vulnerability Exploitability eXchange) statements |
| `regulation_map` | Map SBOM to EO 14028 / NIS2 / CRA / FDA requirements |

## Pairs with

- `meok-attestation-api` — POST results to https://meok-attestation-api.vercel.app/sign for cryptographically signed compliance certs
- `meok-attestation-verify` — public verification of any MEOK-signed cert
- Other MEOK governance MCPs via SOV3 `mcp_bridge_call`

## Pricing

- **Free**: 10 calls/day. No API key required.
- **Pro** £79/mo: unlimited + signed attestations. [Subscribe](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836)
- **Enterprise** £1,499/mo: white-label + on-premise + SLA. hello@meok.ai

## Status

Scaffold v1.0.0 ships the MCP framework + 5 tool stubs. v1.1.0 will add real regulation data ingestion.

If your team needs this MCP fully-loaded faster, ping hello@meok.ai for sponsored development.

## License

MIT © MEOK AI Labs

<!-- mcp-name: io.github.CSOAI-ORG/sbom-cyclonedx-mcp -->
