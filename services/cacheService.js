let sessions = [];
let issuanceResults = [];
let personas = [];
let accesTokens = [];

let walletCodeSessions = [];
let issuerCodeSessions = [];
let codeFlowRequests = [];
let codeFlowRequestsResults = [];

let pushedAuthorizationRequests = new Map();
let sessionsAuthorizationDetail = new Map();
let authCodeAuthorizationDetail = new Map();

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

export function getPushedAuthorizationRequests() {
  return pushedAuthorizationRequests;
}


export function getSessionsAuthorizationDetail() {
  return sessionsAuthorizationDetail;
}


export function getAuthCodeAuthorizationDetail() {
  return authCodeAuthorizationDetail;
}