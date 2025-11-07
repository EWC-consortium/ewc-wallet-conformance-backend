export function resolveCredentialRequestParams({ configurationId, tokenResponse, defaultCredentialIdentifier }) {
  const credentialIdentifier = pickCredentialIdentifier(tokenResponse) || defaultCredentialIdentifier || null;
  const requestPayload = credentialIdentifier
    ? { credential_identifier: credentialIdentifier }
    : { credential_configuration_id: configurationId };

  const storageKey = credentialIdentifier || configurationId;

  return {
    credentialIdentifier,
    requestPayload,
    storageKey,
  };
}

function pickCredentialIdentifier(tokenResponse) {
  if (!tokenResponse || typeof tokenResponse !== "object") return null;

  const authDetails = normalizeAuthorizationDetails(tokenResponse.authorization_details);
  for (const detail of authDetails) {
    if (!detail || typeof detail !== "object") continue;
    if (detail.credential_identifier && typeof detail.credential_identifier === "string") {
      return detail.credential_identifier;
    }
    const identifiers = detail.credential_identifiers;
    if (typeof identifiers === "string" && identifiers) {
      return identifiers;
    }
    if (Array.isArray(identifiers) && identifiers.length > 0) {
      const candidate = identifiers.find((id) => typeof id === "string" && id.length > 0);
      if (candidate) return candidate;
    }
  }

  const topLevelIdentifier = tokenResponse.credential_identifier;
  if (typeof topLevelIdentifier === "string" && topLevelIdentifier) {
    return topLevelIdentifier;
  }
  const topLevelIdentifiers = tokenResponse.credential_identifiers;
  if (typeof topLevelIdentifiers === "string" && topLevelIdentifiers) {
    return topLevelIdentifiers;
  }
  if (Array.isArray(topLevelIdentifiers) && topLevelIdentifiers.length > 0) {
    const candidate = topLevelIdentifiers.find((id) => typeof id === "string" && id.length > 0);
    if (candidate) return candidate;
  }

  return null;
}

function normalizeAuthorizationDetails(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  if (typeof value === "string") {
    const parsed = safeJsonParse(value);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && typeof parsed === "object") return [parsed];
    return [];
  }
  if (typeof value === "object") return [value];
  return [];
}

function safeJsonParse(str) {
  try {
    return JSON.parse(str);
  } catch (e) {
    return null;
  }
}

