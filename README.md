# neurwerk.base - Keycloak API Key Bridge

Keycloak API Key Bridge issues and validates API keys using Keycloak permissions in neurwerk.base. See the [neurwerk.base website](https://base.neurwerk.com/) for more information.

## API-key validation

The internal validation API supports `GET` and `POST` on two endpoints:

| Endpoint | Identity input |
| --- | --- |
| `/validate/neurwerk` | Exactly one `X-Neurwerk-Authorization: Bearer <Neurwerk access key>`. |
| `/validate/proxy` | Exactly one `Proxy-Authorization: Basic <base64(username:Neurwerk access key)>`. |

The dedicated endpoints accept case-insensitive authentication schemes and never
fall back to other headers. They validate access keys, not provider credentials
or OIDC tokens. The gateway must forward only the selected identity header;
provider credentials stay outside the bridge. Proxy usernames are ignored: the
key's owner or managed service account supplies the verified identity.

Dedicated headers are limited to 8,192 ASCII characters. Missing, malformed,
repeated, or comma-joined identity headers return a generic `401` without echoing
the input. Basic credentials require canonical standard base64, valid UTF-8,
nonempty username and key fields, and no ASCII control characters. The first colon
separates the username from the key. The bridge returns errors as
`{"detail":"...","error":{"message":"..."}}`; the gateway owns proxy `407`
responses and authentication challenges.

All three endpoints return the same version-1 decision body and trusted
`x-agentgateway-auth-context` response header. They check key status on every
request and intersect the immutable key grant with the principal's current
permissions. Entitlements are cached for 30 seconds by default. The bridge does
not cache successful key validation or terminate admitted streams; the gateway
must validate each decrypted HTTP request.

Explicit grants may contain `llm:invoke`, `model:<id>:invoke`, `mcp:<id>:invoke`,
`application:<id>:invoke`, and `provider:<id>:company-use`. Resource IDs match
`[A-Za-z0-9][A-Za-z0-9._/-]{0,127}`; wildcards are unsupported. Adding a role to a
user never expands an existing key's grant. New application and company-provider
grants require explicit provisioning and key migration before gateway enforcement.

## Related repositories

| Repository | Description |
| --- | --- |
| [Base chart](https://github.com/neurwerk/k8s_stack_base) | Shared platform charts and release packages that form the foundation of the stack. |
| [Studio](https://github.com/neurwerk/k8s_stack_studio) | Web dashboard and API for operating AI platform services. |
| [Tooling](https://github.com/neurwerk/k8s_stack_tooling) | One container image plus separate CLI tools for setup and operations. |
| [PII Engine](https://github.com/neurwerk/k8s_stack_pii_engine) | Service that uses Presidio to evaluate PII and apply safety policies. |
| [AgentGateway External Processor](https://github.com/neurwerk/k8s_stack_agentgateway_extproc) | Adapter that processes gateway requests and responses with the PII Engine. |
| [Keycloak API Key Bridge](https://github.com/neurwerk/k8s_stack_keycloak_api_key_bridge) | Separate service that issues and validates API keys using Keycloak permissions (**this repo**). |
| [Keycloak Theme](https://github.com/neurwerk/k8s_stack_keycloak_theme) | Customized Keycloak login pages and emails. |
|  |  |
| [Example client chart](https://github.com/neurwerk/k8s_stack_client_example_com) | Reference client configuration and Flux deployment setup to adapt for a new client. |
|  |  |
| [Dify Add-on](https://github.com/neurwerk/k8s_stack_addon_dify) | Optional Dify package with API and web customizations, including single-workspace enforcement. |

## Contributing and support

- **Contributions:** Read [CONTRIBUTING.md](.github/CONTRIBUTING.md) before proposing a change.
- **Bug reports and feature requests:** Use [GitHub Issues](https://github.com/neurwerk/k8s_stack_keycloak_api_key_bridge/issues) for reproducible bugs and clearly scoped feature requests.

## Security

Report vulnerabilities privately by following the instructions in [SECURITY.md](SECURITY.md).

## Licensing

Project-owned content is licensed under the [MIT License](LICENSE). Third-party content retains its upstream license.
