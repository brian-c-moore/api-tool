# API Tool Quick Start Guide

## Overview:
  API Tool is a universal REST API command-line application written in Go.
  It supports multiple authentication methods (none, api_key, bearer, basic, ntlm, digest, oauth2),
  built-in retry logic, pagination, and multi-step chain workflows for complex API sequences.
  For full details, please refer to the man page: [API-TOOL(1)](docs/api-tool.1.man).

## Installation:
  1. Clone the repository and navigate to the project directory.
  2. Build the application:  
     `go build -o build/api-tool ./cmd/api-tool`
  3. Run test examples:  
     `./build/api-tool -config=configs/config.yaml -api=jsonplaceholder -endpoint=get_posts`  
     `./build/api-tool -config=configs/chain_test.yaml --chain`   

## Configuration:
  The tool is configured via a YAML file that defines:

  - apis: A map of API configurations.
      Each API must have:
        • base_url: The API’s base URL.
        • auth_type: Optional API-specific authentication type (if omitted, the global default is used).
        • endpoints: A set of endpoints with path (supports template substitution),
                     method, and optional pagination settings.

  - auth: Global authentication settings.
      Includes a default authentication type and credentials 
      (username, password, api_key, client_id, etc.).

  - retry: Settings for retry logic (max_attempts, backoff_seconds, exclude_errors).

  - logging: Default logging level ("none", "info", or "debug").

  - chain (optional): Defines a multi-step workflow.
      Contains:
        • variables: Initial variable mappings for template substitution.
        • steps: Ordered list of steps, each with a request and/or filter and extraction definitions.

## Usage:

  Single-Request Mode:
    Provide the API name and endpoint defined in your YAML file.
    Example (no authentication):
      api-tool -config=config.yaml -api jsonplaceholder -endpoint get_posts -loglevel=debug

  Chain Workflow Mode:
    Include a "chain" section in your YAML configuration (see test_chain.yaml for an example).
    Example:
      api-tool -config=test_chain.yaml --chain -loglevel=debug

  Help:
    To display the help message and man page, run:
      api-tool -help

## Authentication Examples:
  • None:
      Set auth_type to "none" in your YAML.

  • Basic:
      Set auth_type to "basic" and provide username and password under auth.credentials.
      Example endpoint: /basic-auth/user/passwd.

  • Bearer:
      Set auth_type to "bearer" and export API_TOKEN with your token.

  • NTLM:
      Set auth_type to "ntlm" and provide appropriate domain credentials.

  • Digest:
      Set auth_type to "digest" and provide username and password.

  • OAuth2:
      Set auth_type to "oauth2" and provide client_id, client_secret, token_url, and scope.

For full documentation on the YAML specification and all supported features, please refer to the man page: [API-TOOL(1)](docs/api-tool.1.man).

## License:
  API Tool is released under the MIT License. See the LICENSE file for details.
