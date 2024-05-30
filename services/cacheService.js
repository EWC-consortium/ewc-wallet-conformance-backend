let sessions = [];
let issuanceResults = [];
let personas = [];
let accesTokens = [];

let walletCodeSessions = [];
let issuerCodeSessions = [];
let codeFlowRequests = [];
let codeFlowRequestsResults = [];

export function getPreCodeSessions() {
  return {
    sessions: sessions,
    results: issuanceResults,
    personas: personas,
    accessTokens: accesTokens,
  };
}

export function getAuthCodeSessions() {
  return {
    walletSessions: walletCodeSessions,
    sessions: issuerCodeSessions,
    requests: codeFlowRequests,
    results: codeFlowRequestsResults,
  };
}
