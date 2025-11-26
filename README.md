# SBOM Generator

A Node.js tool for generating SPDX-compliant Software Bill of Materials (SBOM) documents with CPE (Common Platform Enumeration) security references.

## Overview

This project converts component inventory data into standardized SPDX 2.3 format documents, enabling software supply chain security management, vulnerability tracking, and compliance reporting.

## Features

- ✅ **SPDX 2.3 Compliant** - Generates valid SPDX documents following the official specification
- 🔒 **CPE Security References** - Automatic generation of CPE 2.3 strings for vulnerability management
- 📊 **Version-Based Organization** - Supports multiple version categories (CVM3_Car12, CVM3_MY28, RIOx, EIOx)
- 🏢 **Vendor Information** - Includes supplier and product metadata
- 🔄 **Automated Relationships** - Proper SPDX relationship declarations (DESCRIBES)
- 🎯 **Flexible Input Format** - JSON-based component inventory

## Prerequisites

- Node.js (v14 or higher)
- npm

## Installation

1. Clone the repository:
```bash
git clone https://github.com/QbertMF/sbom.git
cd sbom
```

2. Install dependencies:
```bash
npm install
```

## Usage

### Input Data Structure

The tool reads component data from `Sbom.json` organized by version categories:

```json
{
  "CVM3_Car12_Version": [
    {
      "version": "V1.30",
      "component": "Infineon MCAL",
      "vendor": "Infineon AG",
      "product_name": "",
      "part": "",
      "remark": ""
    }
  ],
  "CVM3_MY28_Version": [...],
  "RIOx_version": [...],
  "EIOx_version": [...]
}
```

### Generate SPDX Documents

Run the generator:
```bash
npm start
```

Or:
```bash
node gsbom.js
```

### Output

The tool generates SPDX files for each version category:
- `ECU-CVM3_Car12_Version-manual.spdx.json`
- `ECU-CVM3_MY28_Version-manual.spdx.json`
- `ECU-RIOx_version-manual.spdx.json`
- `ECU-EIOx_version-manual.spdx.json`

### Example Output

```json
{
  "SPDXID": "SPDXRef-DOCUMENT",
  "spdxVersion": "SPDX-2.3",
  "name": "sbom-cvm3_car12_version",
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg-0",
      "name": "Infineon MCAL",
      "supplier": "Organization: Infineon AG",
      "versionInfo": "V1.30",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "externalRefs": [
        {
          "referenceCategory": "SECURITY",
          "referenceLocator": "cpe:2.3:a:Infineon_AG:Infineon_MCAL:V1.30:*:*:*:*:*:*:*",
          "referenceType": "cpe23Type"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-pkg-0"
    }
  ]
}
```

## Configuration

### Customizing Output

Edit `gsbom.js` to modify which version categories to process:

```javascript
// Generate SPDX for specific categories
createSPDXWithCPE('CVM3_Car12_Version');
createSPDXWithCPE('CVM3_MY28_Version');
createSPDXWithCPE('RIOx_version');
createSPDXWithCPE('EIOx_version');
```

### CPE Generation

The tool automatically generates CPE strings following this format:
```
cpe:2.3:part:vendor:product:version:*:*:*:*:*:*:*
```

- **part**: `a` (application), `o` (operating system), `h` (hardware)
- **vendor**: Normalized vendor name (preserves ampersands, replaces spaces with underscores)
- **product**: Component name
- **version**: Component version

## Project Structure

```
sbom/
├── gsbom.js                    # Main SPDX generator script
├── Sbom.json                   # Component inventory data
├── package.json                # Node.js project configuration
├── README.md                   # This file
└── ECU-*.spdx.json            # Generated SPDX documents (output)
```

## Key Functions

### `generateCPE(component)`
Generates CPE 2.3 security reference strings for vulnerability tracking.

### `createSPDXWithCPE(identifier)`
Creates complete SPDX document with packages, relationships, and CPE references for a specific version category.

### `iterateByIdentifier(identifier)`
Alternative function using @spdx/tools library (with post-processing for CPE data).

## Dependencies

- **@spdx/tools** (^0.1.0) - SPDX document creation library

## Standards Compliance

- **SPDX 2.3** - Software Package Data Exchange specification
- **CPE 2.3** - Common Platform Enumeration for security identification
- **ISO/IEC 5962:2021** - SPDX international standard

## Use Cases

- 📋 Software supply chain transparency
- 🔒 Vulnerability management and tracking
- ✅ License compliance reporting
- 🏢 Regulatory compliance (e.g., Executive Order 14028, EU Cyber Resilience Act)
- 🔍 Dependency analysis

## License

CC0-1.0 (as specified in SPDX dataLicense field)

## Author

Markus Foerstel

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Support

For issues or questions, please open an issue on the GitHub repository.

## Version History

- **1.0.0** - Initial release with SPDX 2.3 and CPE support
