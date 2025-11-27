import * as spdx from "@spdx/tools";
import fs from 'fs';

// Load the SBOM data
const sbomData = JSON.parse(fs.readFileSync('./Sbom.json', 'utf8'));

// Function to generate CPE string for a component
function generateCPE(component) {
    // CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    // Example: cpe:2.3:a:Robert_Bosch_AG:CSS2_AB12_D1:0934:*:*:*:*:*:*:*
    
    const part = component.remark && component.remark.toLowerCase() === "os" ? "o" : "a"; // 'a' for application, 'h' for hardware, 'o' for operating system
    
    // CPE allows ampersands (&) - only replace spaces with underscores and remove truly problematic characters
    // Keep alphanumeric, underscores, hyphens, periods, and ampersands
    const vendor = component.vendor ? 
        component.vendor.replace(/\s+/g, "_").replace(/[^a-zA-Z0-9_\-\.&]/g, "") : 
        "unknown_vendor";
    const product = component.component ? 
        component.component.replace(/\s+/g, "_").replace(/[^a-zA-Z0-9_\-\.&]/g, "") : 
        "unknown_product";
    const version = component.version ? 
        component.version.replace(/[^a-zA-Z0-9._\-]/g, "") : 
        "unknown_version";
    
    return `cpe:2.3:${part}:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
}

// Alternative function that creates SPDX manually with CPE included from the start
function createSPDXWithCPE(identifier) {
    if (!sbomData[identifier]) {
        console.log(`Category '${identifier}' not found!`);
        return;
    }

    const categoryData = sbomData[identifier];
    const ecuName = categoryData.ecu_name;
    const components = categoryData.components;

    console.log(`=== ${identifier} (ECU: ${ecuName}) Packages ===`);
    
    // Create SPDX structure manually
    const spdxDocument = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": new Date().toISOString(),
            "creators": ["Person: Markus Foerstel"]
        },
        "name": `SBOM-${ecuName}`,
        "dataLicense": "CC0-1.0",
        "documentNamespace": `http://spdx.org/spdxdocs/${identifier}-${Date.now()}`,
        "packages": [],
        "relationships": []
    };

    // Add packages with CPE information
    components.forEach((component, index) => {
        console.log(`${index + 1}. Component: ${component.component}`);
        console.log(`   Version: ${component.version}`);
        console.log(`   Vendor: ${component.vendor || 'Not specified'}`);
        console.log(`   Product: ${component.product_name || 'Not specified'}`);
        console.log(`   Category: ${component.category || 'OTHER'}`);
        
        const cpeString = generateCPE(component);
        console.log(`   CPE: ${cpeString}`);
        console.log('');

        const packageId = `SPDXRef-pkg-${index}`;
        
        const spdxPackage = {
            "SPDXID": packageId,
            "name": `${component.component}`,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "externalRefs": [
                {
                    "referenceCategory": `${component.category || "SECURITY"}`,
                    "referenceLocator": cpeString,
                    "referenceType": "cpe23Type"
                }
            ]
        };

        // Add vendor information if available
        if (component.vendor) {
            spdxPackage.supplier = `Organization: ${component.vendor}`;
        }

        // Add version if available
        if (component.version) {
            spdxPackage.versionInfo = component.version;
        }

        spdxDocument.packages.push(spdxPackage);
        
        // Add DESCRIBES relationship
        spdxDocument.relationships.push({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": packageId
        });
    });

    // Write the SPDX file
    const filename = `./ECU-${identifier}.spdx.json`;
    fs.writeFileSync(filename, JSON.stringify(spdxDocument, null, 2));
    console.log(`Manual SPDX document with CPE written to: ${filename}`);
}

// Dynamically iterate over all categories in Sbom.json and generate SPDX files
Object.keys(sbomData).forEach(identifier => {
    createSPDXWithCPE(identifier);
});

// <ECU name>_<sw-number>_<sowftware-part-number>.spdx.json
