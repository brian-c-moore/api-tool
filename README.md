# API Tool Quick Start Guide

## Overview
API Tool is a universal REST API command-line application written in Go.
It supports multiple authentication methods (none, api_key, bearer, basic, ntlm, digest, oauth2),
built-in retry logic, pagination, persistent cookie jar management, TLS configuration options,
and multi-step chain workflows for complex API sequences.
For full details, please refer to the man page: [API-TOOL(1)](docs/api-tool.1.man).

## Installation
1. Clone the repository and navigate to the project directory.
2. Build the application:  
   `go build -o build/api-tool ./cmd/api-tool`
3. Run test examples:  
   `./build/api-tool -config=configs/json_test.yaml -api=jsonplaceholder -endpoint=get_posts`  
   `./build/api-tool -config=configs/chain_test.yaml --chain`

## Configuration
API Tool is configured using a YAML file that specifies comprehensive details including API endpoints, authentication methods, retry policies, logging preferences, and multi-step chain workflows.

### apis
A map of API configurations. Each API must include:
  - base_url: The API’s base URL.
  - auth_type: Optional API-specific authentication type (if omitted, the global default is used).
  - tls_skip_verify (optional): Set to true to disable TLS certificate verification. This is useful when
    working with self-signed or invalid certificates. (Defaults to false.)
  - cookie_jar (optional): Set to true to enable persistent cookie jar management. When enabled, cookies
    (such as session tokens) are preserved across multiple requests, which is especially useful in chain workflows.
    (Defaults to false.)
  - endpoints: A set of endpoints with a path (supports template substitution), method, and optional pagination settings.

### auth
Global authentication settings:
  - default: Global default auth type (e.g., "none", "basic", "bearer").
  - credentials: Key/value pairs for credentials (username, password, api_key, client_id, etc.).

### retry
Settings for retry logic:
  - max_attempts: Maximum retry attempts.
  - backoff_seconds: Delay between retries in seconds.
  - exclude_errors: List of HTTP status codes that should not trigger a retry.

### logging
Default logging level ("none", "info", or "debug").

### chain (optional)
Defines a multi-step workflow. Contains:
  - variables: Initial variable mappings for template substitution.
  - steps: Ordered list of steps. Each step may include:
      - request: An API call step.
          - api: The API configuration key to use.
          - endpoint: The endpoint key (from the API configuration).
          - method: Optional override of the HTTP method.
          - data: Optional request body (supports template substitution).
          - headers: Optional headers (supports template substitution).
      - filter: A local step to process JSON using a jq expression.
          - input: JSON input or a variable placeholder.
          - jq: The jq expression to run.
      - extract: A mapping of variable names to jq expressions.
          Extracted values are stored in the chain state and can be referenced in subsequent steps.

## TLS Configuration
Each API configuration may include the tls_skip_verify setting.
When set to true, TLS certificate verification is disabled for that API.
This option is particularly useful for testing against servers with self-signed or invalid certificates.
Use this option with caution in production environments.

## Cookie Jar Management
If the cookie_jar option is enabled for an API, API Tool creates a persistent cookie jar.
This means that cookies (such as session or authentication cookies) are maintained across multiple requests,
even across different chain steps. This is essential for workflows where the session must persist.

## Usage

### Single-Request Mode
Provide the API name and endpoint defined in your YAML file.
Example (no authentication):
  api-tool -config=config.yaml -api jsonplaceholder -endpoint get_posts -loglevel=debug

### Chain Workflow Mode
Include a chain section in your YAML configuration (see configs/chain_test.yaml for an example).
Example:
  api-tool -config=test_chain.yaml --chain -loglevel=debug

### Help
To display the help message and full manual, run:
  api-tool -help

## Authentication Examples
- None:
    Set auth_type to "none" in your YAML.
- Basic:
    Set auth_type to "basic" and provide username and password under auth.credentials.
- Bearer:
    Set auth_type to "bearer" and export API_TOKEN with your token.
- NTLM:
    Set auth_type to "ntlm" and provide appropriate domain credentials.
- Digest:
    Set auth_type to "digest" and provide username and password.
- OAuth2:
    Set auth_type to "oauth2" and provide client_id, client_secret, token_url, and scope.

## License
API Tool is released under the MIT License. See the LICENSE file for details.
