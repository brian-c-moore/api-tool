# api-tool

A flexible command-line tool for automating REST API interactions.

## Overview

**api-tool** is designed to streamline interactions with REST APIs through a powerful command-line interface and configuration files. It supports both simple, single API requests and complex, multi-step chain workflows, making it ideal for various automation tasks.

Whether you need to fetch data, upload files, authenticate using different methods, handle pagination, or orchestrate a sequence of API calls while passing data between them, **api-tool** provides the necessary flexibility and features.

It is built with containerization in mind (e.g., Docker) and can serve as a core component in broader automation pipelines, potentially alongside data processing tools like `etl-tool`.

## Key Features

- **Single Request Mode**: Execute individual API calls directly from the command line with configuration overrides.
- **Chain Workflow Mode**: Define complex, multi-step workflows involving multiple API calls, local data filtering, and variable extraction/passing.
- **Flexible Authentication**: Supports various authentication methods:
  - `none`
  - `api_key` (via config credentials)
  - `basic` (via config credentials)
  - `bearer` (via `API_TOKEN` environment variable or config credentials)
  - `digest` (MD5/SHA-256, with FIPS mode support)
  - `ntlm`
  - `oauth2` (Client Credentials Flow)
- **Robust Pagination**: Handles common pagination strategies automatically:
  - `offset` / `page` (query or body parameters)
  - `cursor` (from response body/header, used in next query/body/URL)
  - `link_header` (RFC 5988 rel="next")
- **Data Extraction**: Extract data from API response bodies using JQ filters or from response headers using regular expressions.
- **File Handling**: Upload raw file content or build multipart/form-data requests. Download response bodies directly to files.
- **Templating**: Utilize Go's `text/template` syntax (`{{.VarName}}`) in configuration values (URLs, headers, data payloads, file paths, JQ filters).
- **Environment Variable Expansion**: Seamlessly expand both Unix-style (`$VAR`, `${VAR}`) and Windows-style (`%VAR%`) environment variables in configuration values.
- **Retry Logic**: Configure automatic retries for requests based on status codes, with exponential backoff and exclusion options.
- **Configurable Logging**: Control log verbosity (`none`, `error`, `warn`, `info`, `debug`).
- **TLS Verification Control**: Option to skip TLS certificate verification for specific APIs.
- **Cookie Jar Support**: Maintain cookies across multiple requests within an API or across steps in a chain.
- **FIPS Mode**: Enforce the use of FIPS-compliant cryptographic algorithms (currently affects Digest authentication, disallowing MD5).

## Installation

### Pre-compiled Binaries (Recommended)

Download the latest pre-compiled binary for your operating system from the Releases Page. *(Add link to your releases here)*

Extract the archive and place the `api-tool` executable in a directory included in your system's `PATH`.

### Build from Source

Ensure you have Go (version 1.22 or later recommended) installed and configured.

```sh
# Clone the repository
git clone <YOUR_REPO_URL_HERE> api-tool  # Replace with your repo URL
cd api-tool

# Tidy dependencies
go mod tidy

# Build the binary
go build -o api-tool ./cmd/api-tool/

# (Optional) Install to your Go bin directory
go install ./cmd/api-tool/
# Make sure $GOPATH/bin (or $HOME/go/bin) is in your PATH
```

## Usage

`api-tool` operates in two primary modes: single request or chain workflow.

```
Usage:
  api-tool [options]

Options:
  -config string        YAML configuration file (default "config.yaml")
  -chain                Run in chain workflow mode (requires a 'chain' section in config)
  -api string           API name for single request mode (required if not using -chain)
  -endpoint string      Endpoint name for single request mode (required if not using -chain)
  -method string        Override HTTP method for single request mode
  -headers string       Additional headers for single request mode (Key:Value,...)
  -data string          JSON payload for POST/PUT requests in single request mode
  -loglevel string      Logging level (none, error, warn, info, debug) (default "info")
  -help                 Show help
```

## Single Request Mode Examples

```sh
# Simple GET request using defaults from config.yaml
api-tool -api myapi -endpoint get_users

# GET request with debug logging, specifying config file
api-tool -config=prod.yaml -api user_service -endpoint get_user_by_id -loglevel=debug

# POST request overriding method and providing data payload
api-tool -api data_service -endpoint create_record -method POST -data '{"name": "New Item", "value": 100}'

# GET request with custom headers
api-tool -api report_api -endpoint download_report -headers "Accept:application/pdf,X-Custom-ID:request123"
```

## Chain Workflow Mode Example

```sh
# Run the chain defined in chain_config.yaml with info logging
api-tool -config=chain_config.yaml -chain -loglevel=info
```

## Configuration File

Configuration is provided in YAML format (e.g., `config.yaml`) and includes:

- Global retry and logging settings
- Global authentication definitions
- API-specific configurations
- Endpoint definitions
- Pagination strategies
- Chain workflows

A full configuration example is provided in the original documentation (see full README).

## Authentication Details

- **none**: No authentication
- **basic**: Requires `username` and `password` in `auth.credentials`
- **api_key**: Requires `api_key` in `auth.credentials`. Sends `Authorization: Bearer <api_key>`
- **bearer**: Uses `API_TOKEN` env var or `bearer_token` from config
- **digest**: Uses `username` and `password`. Supports MD5/SHA-256 (MD5 disabled in FIPS mode)
- **ntlm**: Uses `username` and `password`
- **oauth2**: Client Credentials Flow. Requires `client_id`, `client_secret`, `token_url`

Use environment variables to keep credentials secure (e.g., `%DB_PASSWORD%` or `$DB_PASSWORD`).

## Pagination Details

Pagination is configured per endpoint using the `pagination` block.

Types:
- `offset`, `page`
- `cursor`
- `link_header`

For `offset` and `page`, use:
- `limit`, `offset_param`, `page_param`, `size_param`, `strategy`, `start_page`, etc.

For `cursor`, use:
- `next_field` or `next_header`
- `cursor_usage_mode`: `query`, `body`, `url`
- `cursor_param`

For `link_header`, the `Link` header is parsed according to RFC 5988.

## Chain Workflow Details

Chains are defined under the `chain:` key in the config file.

Each chain contains:
- `variables`: Initial state (env vars merged automatically)
- `steps`: Sequence of operations including API calls, filters, and file operations
- `output`: Optional final output written to a file

Steps may include:
- API request definitions
- Filters using `jq`
- Extract operations (e.g., headers, body values)
- File uploads and downloads
- Header injections with Go templates

## Templating and Environment Variables

Templating uses Go’s `text/template` syntax: `{{.VariableName}}`

Environment variables are expanded before rendering templates:
- Unix-style: `$VAR` or `${VAR}`
- Windows-style: `%VAR%`

You can mix environment and chain variables in paths, headers, data, filters, and more.

## FIPS Mode

Enable FIPS mode via:

```yaml
fips_mode: true
```

In FIPS mode:
- Digest auth will not allow MD5
- Other cryptographic functions depend on Go and OS crypto library

## Testing

Run tests with:

```sh
# Ensure dependencies are tidy
go mod tidy

# Run all tests
go test ./...

# Run tests with verbose output
go test ./... -v
```

Example test output:

```
?       api-tool/cmd/api-tool         [no test files]
ok      api-tool/internal/app         0.195s
ok      api-tool/internal/auth        0.330s
ok      api-tool/internal/chain       0.606s
ok      api-tool/internal/config      0.422s
ok      api-tool/internal/executor    0.743s
ok      api-tool/internal/httpclient  0.882s
ok      api-tool/internal/jq          1.011s
ok      api-tool/internal/logging     1.123s
ok      api-tool/internal/template    1.143s
ok      api-tool/internal/util        0.992s
```

Tests use mocks for external dependencies (HTTP, file I/O, jq) for fast and reliable execution.

## Contributing

Contributions are welcome! Follow these steps:

1. Fork the repository
2. Create a feature branch:
   ```sh
   git checkout -b feature/my-feature
   ```
3. Make changes. Format and lint code:
   ```sh
   go fmt ./...
   ```
4. Add or update tests
5. Run all tests and ensure they pass:
   ```sh
   go test ./...
   ```
6. Commit and push:
   ```sh
   git commit -am "Add my feature"
   git push origin feature/my-feature
   ```
7. Open a Pull Request

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments
This tool was designed to address a gap I saw in existing automation tools. Golang seemed like the best choice to accomplish my goals, but my experience has been with other programming languages. I’ve leveraged AI for assistance with coding and as a way to teach myself a new language while building something useful. The overall design, architecture, and direction are entirely my own.
