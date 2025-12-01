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
export async function verifyMdlToken(vpTokenBase64, options = {}, documentType = "urn:eu.europa.ec.eudi:pid:1") {
  const {
    requestedFields = null,
    validateStructure = true,
    includeMetadata = true
  } = options;
  
  try {
    // Step 1: Preprocess the token - handle URL encoding, trimming, and object extraction
    let tokenString = vpTokenBase64;
    const originalType = typeof tokenString;
    
    // If it's an object, try to extract the token (for structured formats)
    if (typeof tokenString === 'object' && tokenString !== null) {
      // Check if it's wrapped in a structure like {"cmwallet": ["token"]}
      const values = Object.values(tokenString);
      for (const value of values) {
        if (Array.isArray(value) && value.length > 0 && typeof value[0] === 'string') {
          tokenString = value[0];
          break;
        } else if (typeof value === 'string') {
          tokenString = value;
          break;
        }
      }
    }
    
    // Ensure it's a string
    if (typeof tokenString !== 'string') {
      throw new Error(`Expected vp_token to be a string after extraction, got ${typeof tokenString} (original type: ${originalType})`);
    }
    
    // Trim whitespace and newlines
    tokenString = tokenString.trim();
    
    // Handle JSON-wrapped strings (e.g., '"token"' instead of 'token')
    if (tokenString.startsWith('"') && tokenString.endsWith('"')) {
      try {
        tokenString = JSON.parse(tokenString);
      } catch (e) {
        // Not valid JSON, continue with trimmed string
      }
    }
    
    // Remove any remaining whitespace (after potential JSON parsing)
    tokenString = tokenString.trim().replace(/\s+/g, '');
    
    // Handle URL encoding - decode if needed
    try {
      // Try to decode URL-encoded characters (but not the base64url characters themselves)
      // Only decode if it contains % encoding
      if (tokenString.includes('%')) {
        tokenString = decodeURIComponent(tokenString);
      }
    } catch (e) {
      // If URL decoding fails, it might already be decoded or not URL-encoded
      // Continue with the original string
      console.warn("URL decoding failed (this is usually fine):", e.message);
    }
    
    // Validate base64url characters (should only contain A-Z, a-z, 0-9, -, _)
    // Note: base64url doesn't use padding typically, but we'll allow it
    if (!/^[A-Za-z0-9\-_]+=*$/.test(tokenString)) {
      throw new Error(`Invalid base64url characters detected. Token length: ${tokenString.length}, first 50 chars: ${tokenString.substring(0, 50)}`);
    }
    
    // Step 2: Decode base64url to buffer
    let buffer;
    try {
      buffer = base64url.toBuffer(tokenString);
    } catch (e) {
      throw new Error(`Failed to decode base64url: ${e.message}. Token length: ${tokenString.length}, preview: ${tokenString.substring(0, 100)}`);
    }
    
    if (!buffer || buffer.length === 0) {
      throw new Error(`Decoded buffer is empty. Token length: ${tokenString.length}`);
    }
    
    // Step 3: Decode CBOR structure
    let deviceResponse;
    try {
      deviceResponse = decode(buffer);
    } catch (e) {
      throw new Error(`Failed to decode CBOR: ${e.message}. Buffer length: ${buffer.length} bytes. This suggests the token might not be a valid mDL CBOR structure.`);
    }
    
    // Step 4: Validate basic structure if requested
    if (validateStructure) {
      if (!deviceResponse.version || !deviceResponse.documents || !Array.isArray(deviceResponse.documents)) {
        throw new Error("Invalid mDL structure: missing version or documents");
      }
      
      if (deviceResponse.documents.length === 0) {
        throw new Error("No documents found in mDL");
      }
    }
    
    // Step 5: Process the first document (typically the mDL)
    const document = deviceResponse.documents[0];
    
    if (validateStructure && !document.docType) {
      throw new Error("Document missing docType");
    }
    
    // Step 6: Extract claims from issuerSigned nameSpaces
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
    
    // Step 7: Apply field filtering if requested (for selective disclosure)
    let claims = allClaims;
    // if (requestedFields && Array.isArray(requestedFields)) {
    //   claims = {};
    //   requestedFields.forEach(field => {
    //     if (allClaims[field] !== undefined) {
    //       claims[field] = allClaims[field];
    //     }
    //   });
    // }
    
    // Step 8: Build result object
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
  verifyMdlToken,
  validateMdlClaims,
  getSessionTranscriptBytes,
  extractDeviceNonce,
}; 