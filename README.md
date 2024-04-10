# EWC Wallet Conformance Backend Service

## Introduction

This service implements two crucial RFCs specified by the EU Digital Identity Wallet Consortium (EWC), contributing to the large-scale pilot for the European Digital Identity Wallet as part of the eIDAS 2.0 regulation. By adhering to these RFCs, this service aims to ensure interoperability within the European Digital Identity Wallet Consortium (EWC) Ecosystem, facilitating a standardized approach for both credential issuance and presentation.

### RFCs Implemented

- [**RFC001**](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc001-issue-verifiable-credential.md): Implements the OID4VCI (OpenID for Verifiable Credential Issuance) workflow for credential issuers.
- [**RFC002**](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc002-present-verifiable-credentials.md): Implements the OIDC4VP (OpenID for Verifiable Presentations) workflow for verifiers (relying parties).

## Features

- **Credential Issuance**:  Implements the OID4VCI workflow, ensuring a standardized approach to verifiable credential issuance across any issuer within the EWC Ecosystem. Supports both authorization code flow and pre-authorized code flow for issuing credentials to wallet holders.
- **Credential Presentation**:  Implements the OIDC4VP workflow, ensuring a standardized approach to verifiable credential presentation across any verifier within the EWC Ecosystem. Facilitates the presentation of credentials by wallet holders to verifiers using both same-device and cross-device verification flows.
- **Interoperability**: Designed with interoperability at its core, this service promotes seamless integration within the EUDI wallet ecosystem, adhering to the specifications and requirements of the ARF.

## Getting Started

1. Clone the repository:
   ```bash
   git clone <repository-url>
2. Navigate to the project directory:
   ```bash
    cd ewc-wallet-conformance-backend
3. Install dependencies
   ```bash
    npm install
4. Start the service 
   ```bash
    npm start

Optionally, if you want to use a tunneling provider for local deployment to ensure https is enabled (which is required by the spec) you can configure your tunnel
endpoint inside package.json:
     ```bash
     "dev": "SERVER_URL=https://4150-2a02-587-8701-de00-c100-84c1-e7c9-8738.ngrok-free.app node server.js" 

## Getting Started
Refer to the individual RFC documentation for detailed usage instructions:
- [**RFC001**](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc001-issue-verifiable-credential.md)
- [**RFC002**](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc002-present-verifiable-credentials.md)

## Contributing
Contributions to enhance the functionality and interoperability of the wallet provider service are welcome. Please submit pull requests with a clear explanation of your changes or open issues for bugs and feature requests.

## License
TBD

## References

1. OpenID Foundation: [OpenID for Verifiable Credential Issuance (OID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html)
2. OpenID Foundation: [OpenID for Verifiable Presentations (OID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html )
3. European Commission: [The European Digital Identity Wallet Architecture and Reference Framework (ARF)](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases)
