# Keycloak API Key Bridge

The bridge issues personal API keys and validates personal and managed keys for AgentGateway. This repository owns the Python service, personal-key storage schema, tests, and container image. Keycloak owns identities and permissions; Base owns deployment charts; Studio provides the management interface.

- [Architecture](architecture/README.md): issuance, validation, revocation, and component boundaries.
- [Development](development/README.md): local setup and checks.
- [Operations](operations/README.md): settings, dependencies, verification, and recovery boundaries.
