let sessions = [];
let issuanceResults = [];

let walletCodeSessions = [];
let issuerCodeSessions = [];
let codeFlowRequests = [];
let codeFlowRequestsResults = [];

export function getPreCodeSessions() {
  return {
    sessions: sessions,
    results: issuanceResults,
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


