# Issuer Service for the European Wallet Ecosystem

## Introduction

This issuer service is designed to implement the OpenID Foundation's workflow for Verifiable Credential Issuance (OID4VCI), adhering to the specifications set forth by the EU Digital Identity
Wallet Consortium (EWC). By following the detailed requirements and guidelines of the EWC project, specifically as outlined in the [EWC RFC001](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc001-issue-verifiable-credential.md), this service aims to streamline the issuance of verifiable credentials across the European Wallet Ecosystem.

## Features

- **OID4VCI Compliance**: Implements the OID4VCI workflow, ensuring a standardized approach to verifiable credential issuance across any issuer within the European Wallet Ecosystem.
- **Interoperability**: Designed with interoperability at its core, this service promotes seamless integration within the EUDI wallet ecosystem, adhering to the specifications and requirements of the ARF.
 

## Reference Specifications

1. **OpenID for Verifiable Credential Issuance (OID4VCI)**: Follows the OpenID Foundation's specifications for verifiable credential issuance. For more details, see the [OpenID Foundation (2023), 'OpenID for Verifiable Credential Issuance (OID4VCI)'](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html). Accessed: January 10, 2024.

2. **The European Digital Identity Wallet Architecture and Reference Framework (ARF)**: Adheres to the European Commission's specifications for digital identity wallets. For additional information, consult the [European Commission (2023) The European Digital Identity Wallet Architecture and Reference Framework (2023-04, v1.1.0)](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases). Accessed: October 16, 2023.

## Getting Started

To get started with the issuer service, follow these steps:
update package.json with the url that the services will run on (requires https)
e.g. `"dev": "SERVER_URL=https://6522-2001-648-2050-6021-4965-2baf-2b20-4a1.ngrok-free.app node server.js"`
start the issuer service
`npm run dev`

## Usage

TBD

## Contributing

Contributions are welcome to enhance the functionalities of the issuer service, ensuring it remains up-to-date with the evolving standards of the European Wallet Ecosystem.

## License

(Include license information here, e.g., MIT, GPL, etc.)
