# SBOM Generator

A Node.js tool for generating SPDX-compliant Software Bill of Materials (SBOM) documents with CPE (Common Platform Enumeration) security references.

## Overview

This project converts component inventory data into standardized SPDX 2.3 format documents, enabling software supply chain security management, vulnerability tracking, and compliance reporting.

## Key Features

### Automatic Dynamic Processing
- Discovers all ECU/version categories in `Sbom.json` automatically
- No manual configuration needed for new categories
- Each category generates its own SPDX file

### CPE Generation
The tool automatically generates CPE 2.3 security reference strings:

**Features:**
- Detects operating system components from "OS" remark
- Preserves vendor names with ampersands (e.g., "ETAS GmbH & Co")
- Normalizes component names and versions to CPE format
- Generates: `cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`

**Example CPE strings:**
- `cpe:2.3:a:Infineon_AG:MC-ISAR_AS422_TC3xx_MCAL:V1.30:*:*:*:*:*:*:*`
- `cpe:2.3:o:Embedded_Office_GmbH_&_Co._KG:uC_OS-MPU:1.4.0:*:*:*:*:*:*:*` (OS detected from remark)
- `cpe:2.3:a:ETAS_GmbH:CycurHSM:2.7.13.r0_v3:*:*:*:*:*:*:*`

### Component Classification
- **SECURITY** - For security-critical components (CycurHSM, CycurLIB)
- **OTHER** - For general components
- Classification affects SPDX external reference categories

### ECU-Based Organization
- Each category has an associated ECU name (CVM3, RIOx, EIOx)
- SPDX document names reflect ECU identifiers
- Clear mapping between categories and ECUs

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

The tool reads component data from `Sbom.json` organized by ECU/version categories. Each category contains an `ecu_name` and a `components` array:

```json
{
  "CVM3_Car12_Version": {
    "ecu_name": "CVM3",
    "components": [
      {
        "version": "V1.30",
        "component": "MC-ISAR_AS422_TC3xx_MCAL",
        "vendor": "Infineon AG",
        "product_name": "",
        "part": "",
        "remark": "",
        "category": "OTHER"
      },
      {
        "version": "2.7.13.r0_v3",
        "component": "CycurHSM",
        "vendor": "ETAS GmbH",
        "product_name": "CycurHSM",
        "part": "",
        "remark": "",
        "category": "SECURITY"
      }
    ]
  },
  "CVM3_MY28_Version": { ... },
  "RIOx_version": { ... },
  "EIOx_version": { ... }
}
```

### Component Fields

Each component in the `components` array contains:
- **version** - Software version identifier
- **component** - Component name
- **vendor** - Vendor/manufacturer name (preserved with ampersands for accuracy)
- **product_name** - Product identifier (optional)
- **part** - Part number (optional)
- **remark** - Additional remarks (e.g., "OS" for operating systems)
- **category** - Security classification ("SECURITY" or "OTHER")

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

The tool automatically discovers all categories in `Sbom.json` and generates SPDX files for each one:
- `ECU-CVM3_Car12_Version.spdx.json`
- `ECU-CVM3_MY28_Version.spdx.json`
- `ECU-RIOx_version.spdx.json`
- `ECU-EIOx_version.spdx.json`

Each file contains the complete SPDX 2.3 document with CPE security references for all components in that category.

### Example Output

```json
{
  "SPDXID": "SPDXRef-DOCUMENT",
  "spdxVersion": "SPDX-2.3",
  "name": "SBOM-CVM3",
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg-0",
      "name": "MC-ISAR_AS422_TC3xx_MCAL",
      "supplier": "Organization: Infineon AG",
      "versionInfo": "V1.30",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "externalRefs": [
        {
          "referenceCategory": "OTHER",
          "referenceLocator": "cpe:2.3:a:Infineon_AG:MC-ISAR_AS422_TC3xx_MCAL:V1.30:*:*:*:*:*:*:*",
          "referenceType": "cpe23Type"
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-pkg-1",
      "name": "CycurHSM",
      "supplier": "Organization: ETAS GmbH",
      "versionInfo": "2.7.13.r0_v3",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "externalRefs": [
        {
          "referenceCategory": "SECURITY",
          "referenceLocator": "cpe:2.3:a:ETAS_GmbH:CycurHSM:2.7.13.r0_v3:*:*:*:*:*:*:*",
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
    },
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-pkg-1"
    }
  ]
}
```

## Configuration

### Dynamic Category Processing

The program automatically discovers and processes all categories in `Sbom.json`:

```javascript
// Dynamically iterate over all categories in Sbom.json and generate SPDX files
Object.keys(sbomData).forEach(identifier => {
    createSPDXWithCPE(identifier);
});
```

This means:
- **No hardcoded categories** - New categories are automatically detected
- **Scalable** - Add categories to Sbom.json and they're processed automatically
- **Flexible** - Each category can have different ECU names and components

### Customizing Component Categories

Edit component entries in `Sbom.json` to classify them as "SECURITY" or "OTHER":

```json
{
  "component": "CycurHSM",
  "category": "SECURITY"  // Security-related component
},
{
  "component": "Infineon SafetyPack",
  "category": "OTHER"     // General component
}
```

This affects the `referenceCategory` in SPDX external references.

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
