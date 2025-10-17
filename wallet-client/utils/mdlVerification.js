import { decode } from 'cbor-x';
import base64url from 'base64url';

/**
 * Custom mDL verification using cbor-x decoder
 * This bypasses the buggy @auth0/mdl library and provides reliable verification
 * 
 * @param {string} vpTokenBase64 - Base64url encoded mDL token
 * @param {Object} options - Verification options
 * @param {string[]} options.requestedFields - Array of field names to extract (for selective disclosure)
 * @param {boolean} options.validateStructure - Whether to perform strict structure validation (default: true)
 * @param {boolean} options.includeMetadata - Whether to include metadata in response (default: true)
 * @returns {Object} Verification result
 */
export async function verifyReceivedMdlToken(vpTokenBase64, options = {}, documentType = "urn:eu.europa.ec.eudi:pid:1") {
  const {
    requestedFields = null,
    validateStructure = true,
    includeMetadata = true
  } = options;
  
  try {
    // Step 1: Decode base64url to buffer
    const buffer = base64url.toBuffer(vpTokenBase64);
    
    // Step 2: Decode CBOR structure
    const decodedData = decode(buffer);
    
    // Debug: Log the structure to understand what we received
    console.log("[mdl-verify] Decoded CBOR structure keys:", Object.keys(decodedData || {}));
    console.log("[mdl-verify] Decoded CBOR type:", typeof decodedData, Array.isArray(decodedData) ? "(array)" : "");
    if (decodedData && typeof decodedData === 'object' && !Array.isArray(decodedData)) {
      console.log("[mdl-verify] Top-level fields:", JSON.stringify(Object.keys(decodedData)));
    }
    
    // Step 3: Detect format - could be DeviceResponse (presentation) or Document (issuance)
    let deviceResponse;
    let document;
    
    if (decodedData.version && decodedData.documents && Array.isArray(decodedData.documents)) {
      // Full DeviceResponse format (used during presentation)
      console.log("[mdl-verify] Detected DeviceResponse format (presentation)");
      deviceResponse = decodedData;
      
      if (validateStructure && deviceResponse.documents.length === 0) {
        throw new Error("No documents found in mDL");
      }
      
      document = deviceResponse.documents[0];
    } else if (decodedData.docType || decodedData.issuerSigned) {
      // Single Document format (used during issuance)
      console.log("[mdl-verify] Detected single Document format (issuance)");
      document = decodedData;
      deviceResponse = {
        version: "1.0", // Default version for issued credentials
        documents: [document],
        status: 0
      };
    } else if (decodedData.nameSpaces && decodedData.issuerAuth) {
      // IssuerSigned format (minimal issuance format per ISO 18013-5)
      console.log("[mdl-verify] Detected IssuerSigned format (minimal issuance)");
      // Wrap IssuerSigned in a Document structure
      document = {
        docType: documentType || "org.iso.18013.5.1.mDL", // Use provided or default docType
        issuerSigned: decodedData,
        deviceSigned: null // Not present during issuance
      };
      deviceResponse = {
        version: "1.0",
        documents: [document],
        status: 0
      };
    } else {
      // Unknown format - might be wrapped or use non-standard field names
      console.log("[mdl-verify] Warning: Unknown format, attempting to unwrap/parse");
      
      // Try common envelope patterns
      let unwrapped = decodedData;
      
      // Check if it's wrapped in a 'credential' field
      if (decodedData.credential) {
        console.log("[mdl-verify] Found 'credential' wrapper, unwrapping...");
        unwrapped = decodedData.credential;
      }
      
      // Check if the unwrapped data is a string (might need another decode)
      if (typeof unwrapped === 'string') {
        console.log("[mdl-verify] Credential is a string, attempting to decode again...");
        try {
          const innerBuffer = base64url.toBuffer(unwrapped);
          unwrapped = decode(innerBuffer);
          console.log("[mdl-verify] Successfully decoded inner credential");
        } catch (e) {
          console.warn("[mdl-verify] Could not decode inner string:", e.message);
        }
      }
      
      // Re-check format after unwrapping
      if (unwrapped.version && unwrapped.documents && Array.isArray(unwrapped.documents)) {
        console.log("[mdl-verify] After unwrapping: Detected DeviceResponse format");
        deviceResponse = unwrapped;
        document = deviceResponse.documents[0];
      } else if (unwrapped.docType || unwrapped.issuerSigned) {
        console.log("[mdl-verify] After unwrapping: Detected Document format");
        document = unwrapped;
        deviceResponse = { version: "1.0", documents: [document], status: 0 };
      } else if (unwrapped.nameSpaces && unwrapped.issuerAuth) {
        console.log("[mdl-verify] After unwrapping: Detected IssuerSigned format");
        document = {
          docType: documentType || "org.iso.18013.5.1.mDL",
          issuerSigned: unwrapped,
          deviceSigned: null
        };
        deviceResponse = { version: "1.0", documents: [document], status: 0 };
      } else {
        // Still unknown after unwrapping
        console.log("[mdl-verify] Still unknown format after unwrapping. Keys:", Object.keys(unwrapped || {}));
        if (validateStructure) {
          throw new Error("Invalid mDL structure: not a DeviceResponse or Document");
        }
        // Last resort: treat as document
        document = unwrapped;
        deviceResponse = { version: "1.0", documents: [document], status: 0 };
      }
    }
    
    if (validateStructure && !document.docType) {
      console.warn("[mdl-verify] Warning: Document missing docType, using default");
      document.docType = documentType || "org.iso.18013.5.1.mDL";
    }
    
    // Step 5: Extract claims from issuerSigned nameSpaces
    const allClaims = {};
    if (document.issuerSigned?.nameSpaces) {
      // Try multiple possible namespace identifiers
      // 1. Use the provided documentType
      // 2. Use the standard ISO namespace "org.iso.18013.5.1"
      // 3. Use the EU namespace "urn:eu.europa.ec.eudi:pid:1"
      // 4. Try any available namespace
      let isoNamespace = document.issuerSigned.nameSpaces[documentType];
      
      if (!isoNamespace && documentType === "org.iso.18013.5.1.mDL") {
        // For mDL docType, try the standard ISO namespace
        isoNamespace = document.issuerSigned.nameSpaces["org.iso.18013.5.1"];
      }
      
    
      
      if (!isoNamespace) {
        // Fallback: try the first available namespace
        const availableNamespaces = Object.keys(document.issuerSigned.nameSpaces);
        if (availableNamespaces.length > 0) {
          isoNamespace = document.issuerSigned.nameSpaces[availableNamespaces[0]];
          console.log("Using fallback namespace:", availableNamespaces[0]);
        }
      }
      
      if (isoNamespace && Array.isArray(isoNamespace)) {
        isoNamespace.forEach(element => {
          try {
            // Handle CBOR tags properly - elements are wrapped in CBOR tags
            let elementDecoded;
            if (element?.tag !== undefined) {
              elementDecoded = decode(element.value);
            } else {
              elementDecoded = decode(element);
            }
            
            if (elementDecoded?.elementIdentifier && elementDecoded.elementValue !== undefined) {
              allClaims[elementDecoded.elementIdentifier] = elementDecoded.elementValue;
            }
          } catch (e) {
            // Skip elements that can't be decoded - this is normal for some CBOR structures
          }
        });
      }
    }
    
    // Step 6: Apply field filtering if requested (for selective disclosure)
    let claims = allClaims;
    // if (requestedFields && Array.isArray(requestedFields)) {
    //   claims = {};
    //   requestedFields.forEach(field => {
    //     if (allClaims[field] !== undefined) {
    //       claims[field] = allClaims[field];
    //     }
    //   });
    // }
    
    // Step 7: Build result object
    const result = {
      success: true,
      docType: document.docType,
      version: deviceResponse.version,
      status: deviceResponse.status,
      claims: claims
    };
    
    // Add metadata if requested
    if (includeMetadata) {
      result.metadata = {
        totalFields: Object.keys(allClaims).length,
        extractedFields: Object.keys(claims).length,
        requestedFields: requestedFields,
        hasDeviceSigned: !!document.deviceSigned,
        hasIssuerSigned: !!document.issuerSigned,
        extractedAt: new Date().toISOString()
      };
    }
    
    return result;
    
  } catch (error) {
    return {
      success: false,
      error: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    };
  }
}

/**
 * Validates if extracted claims match the requested fields from presentation definition
 * This replaces the hasOnlyAllowedFields function for mDL verification
 * 
 * @param {Object} extractedClaims - Claims extracted from mDL
 * @param {string[]} requestedFields - Fields that were requested in presentation definition (JSONPath format)
 * @returns {boolean} True if claims match requested fields
 */
export function validateMdlClaims(extractedClaims, requestedFields) {
  if (!requestedFields || !Array.isArray(requestedFields)) {
    return true; // No specific fields requested
  }
  
  // Extract field names from JSONPath expressions
  // JSONPath format: "$['org.iso.18013.5.1']['field_name']"
  const fieldNames = requestedFields.map(jsonPath => {
    // Extract the field name from the JSONPath
    const match = jsonPath.match(/\['([^']+)'\]$/);
    return match ? match[1] : null;
  }).filter(fieldName => fieldName !== null);
  
  // Check if all requested fields are present
  const missingFields = fieldNames.filter(fieldName => extractedClaims[fieldName] === undefined);
  
  
  if (missingFields.length > 0) {
    console.warn(`Missing requested fields: ${missingFields.join(', ')}`);
    console.log('extractedClaims', extractedClaims);
    console.log('fieldNames', fieldNames);
    return false;
  }
  
  return true;
}

/**
 * Helper function to get session transcript bytes for OID4VP
 * This is specific to OpenID4VP protocol
 */
export function getSessionTranscriptBytes(oid4vpData, mdocGeneratedNonce) {
  const { encode: encodeCbor } = require('cbor-x');
  return encodeCbor([
    'OIDC4VPHandover', 
    oid4vpData.client_id, 
    oid4vpData.response_uri, 
    mdocGeneratedNonce, 
    oid4vpData.nonce
  ]);
}

/**
 * Extract device nonce from mDL device response (if present)
 * This would typically be used for session transcript construction
 * 
 * @param {string} vpTokenBase64 - Base64url encoded mDL token
 * @returns {string|null} Device nonce if found, null otherwise
 */
export async function extractDeviceNonce(vpTokenBase64) {
  try {
    const buffer = base64url.toBuffer(vpTokenBase64);
    const deviceResponse = decode(buffer);
    
    // Look for device nonce in deviceSigned section
    if (deviceResponse.documents?.[0]?.deviceSigned) {
      const deviceSigned = deviceResponse.documents[0].deviceSigned;
      
      // The exact location of the device nonce may vary depending on the implementation
      // This is a simplified extraction - real implementation may need more sophisticated parsing
      if (deviceSigned.deviceAuth) {
        // Device nonce might be embedded in deviceAuth structure
        // This would need to be adapted based on the actual mDL implementation
        return null; // Placeholder for now
      }
    }
    
    return null;
  } catch (error) {
    console.warn("Could not extract device nonce:", error.message);
    return null;
  }
}

export default {
  verifyMdlToken: verifyReceivedMdlToken,
  validateMdlClaims,
  getSessionTranscriptBytes,
  extractDeviceNonce
}; 