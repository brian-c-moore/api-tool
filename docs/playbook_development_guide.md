# api-tool Playbook Development Guide

This guide provides best practices, tips, tricks, and examples for developing effective automation playbooks using `api-tool`, focusing primarily on the `chain` workflow mode.

## 1. Introduction

`api-tool` shines when automating sequences of API interactions. A "playbook" in this context refers to the `chain` configuration within your `config.yaml` file, defining the steps, data flow, and logic for your automation task. This guide will help you build robust, maintainable, and efficient playbooks.

## 2. Core Concepts Review

Before diving into playbooks, ensure you understand these core `api-tool` concepts:

*   **Configuration (`config.yaml`):** The central hub defining APIs, authentication, steps, retry logic, logging, etc.
*   **Chain Workflow Mode (`-chain`):** Executes a sequence of defined steps.
*   **Steps:** Individual operations within a chain (`request`, `filter`).
*   **State:** A map holding variables (`chain.variables`, environment variables, extracted values) passed between steps. Values are generally stored as strings.
*   **Templating (`{{.VarName}}`):** Dynamically inserting state variables into step configurations (URLs, headers, data, paths, filters). Uses Go's `text/template` engine with the `Option("missingkey=error")` setting (missing variables cause errors).
*   **Environment Variable Expansion (`$VAR`, `%VAR%`):** Replacing placeholders with environment variables *before* templating. Undefined variables become empty strings.
*   **Extraction (`extract`):** Pulling data from step results (response headers via regex, response body via JQ, filter output) into the state.
*   **Authentication:** Various methods (`none`, `api_key`, `basic`, `bearer`, `digest`, `ntlm`, `oauth2`) configured globally or per-API. FIPS mode restricts Digest MD5.
*   **Pagination:** Automatic handling for common API patterns (`offset`, `page`, `cursor`, `link_header`). Supports query/body parameters, totals, max pages, etc. Can force initial params.
*   **File Handling:** Uploading raw file content (`upload_body_from`) or multipart forms (`form_data`/`file_fields`). Downloading response bodies (`download_to`). Paths support templating/env vars.
*   **JQ Integration:** Using the external `jq` command (must be installed and in PATH) for JSON processing within `filter` steps or `extract` sections.
*   **Retry Logic:** Configurable retries on server errors (5xx by default) or network errors, with **fixed** backoff (`backoff_seconds`) and status code exclusions (`exclude_errors`).
*   **HTTP Client Config:** Control TLS verification (`tls_skip_verify`), force HTTP/1.1 (`ForceHTTP1`), set API-specific timeouts (`TimeoutSeconds`), and manage cookies (`cookie_jar`).

## 3. When to Use Chain Mode (Playbooks)

Use `chain` mode when your task involves:

1.  **Multiple dependent API calls:** e.g., Authenticate -> Fetch Resource List -> Fetch Detail for one Resource -> Update Resource.
2.  **Passing data between calls:** Extracting an ID from one response to use in the URL or body of the next request.
3.  **Dynamic Request Construction:** Using extracted state variables within request templates (URLs, headers, data).
4.  **Local data processing:** Using `filter` steps with `jq` to transform or reshape data between API calls.
5.  **Complex setup:** Combining file uploads/downloads with API interactions.
6.  **Needing intermediate state:** Storing values (tokens, IDs, status codes) temporarily for later use in the chain.

If you only need a single, independent API call (even with pagination), the simpler Single Request Mode (`-api`/`-endpoint`) might suffice.

## 4. Configuration Best Practices

*   **Clear Naming:** Use descriptive names for APIs (`apis.<name>`), endpoints (`endpoints.<name>`), chain steps (`steps.name`), and variables (`chain.variables`, `extract` keys). This vastly improves readability and debugging.
*   **Environment Variables for Secrets:** **Never** hardcode sensitive information (passwords, API keys, tokens) directly in `config.yaml`. Use environment variable expansion (`$SECRET_KEY`, `%DB_PASSWORD%`) and inject these secrets into the execution environment (e.g., Docker secrets, CI/CD variables).
    ```yaml
    # Good: Use environment variables
    auth:
      credentials:
        username: "%API_USER%"
        password: "$API_PASSWORD"
        api_key: "${SERVICE_API_KEY}"
        bearer_token: "$BEARER_TOKEN" # If API_TOKEN env var isn't used

    # Bad: Hardcoded secrets
    # auth:
    #   credentials:
    #     username: "admin"
    #     password: "Password123"
    ```
*   **Modular Configuration (Logical Separation):** While `api-tool` primarily uses one config file per run (`-config`), structure your YAML logically. Group related APIs and endpoints. Use YAML comments (`#`) liberally to explain sections, endpoints, and complex steps. For very different automation tasks, consider separate `config.yaml` files (e.g., `user_onboarding.yaml`, `report_generation.yaml`).
*   **Default Settings:** Define sensible global defaults for `retry`, `auth`, and `logging` at the top level. Override per-API or per-endpoint only when necessary.
*   **API Client Settings:** Leverage API-level settings like `TimeoutSeconds` for slow APIs or `ForceHTTP1` if interacting with older systems or specific proxies. Use `tls_skip_verify` cautiously for non-production environments.
*   **Start Simple:** Begin with the basic API calls working, then layer in extraction, templating, file handling, and filtering incrementally. Test each addition.

## 5. Authentication Strategies

*   **Use Env Vars for Bearer:** Prefer setting the `API_TOKEN` environment variable for `bearer` auth over defining `bearer_token` in `auth.credentials`, as the environment variable often integrates better with CI/CD systems and secret management tools. Remember `API_TOKEN` takes precedence.
*   **OAuth2:** The `oauth2` (Client Credentials) type handles token fetching and refreshing automatically. Just provide `client_id`, `client_secret`, `token_url` (and optional `scope`) in `auth.credentials`. `api-tool` manages the `Authorization: Bearer` header for calls using that API configuration.
*   **API-Specific Auth:** If different services require different auth methods, define `auth_type` within each API block (`apis.<api_name>.auth_type`).
*   **Digest & FIPS:** If using `digest` auth, be aware that setting `fips_mode: true` will disallow the MD5 algorithm, potentially causing failures if the server only supports MD5.

## 6. Mastering Templating and Variables

*   **Execution Order:** Remember the two passes:
    1.  **Environment Variable Expansion:** `$VAR`/`%VAR%` are replaced first across the entire loaded config string. Undefined variables become empty strings.
    2.  **Go Templating:** `{{.VarName}}` is rendered during step execution using the *current* chain state map.
*   **Mixing:** You can combine them:
    ```yaml
    # Get base URL from env, use dynamic state var in endpoint path
    # In config:
    apis:
      myService:
        base_url: "$SERVICE_BASE_URL"
        endpoints:
          get_user:
            path: "/users/{{.USER_ID}}/profile" # Path template
    # In chain step:
    request:
      api: myService
      endpoint: get_user # Path template is rendered when step executes
    ```
*   **Accessing State:** Inside templates (`{{ }}`), use dot notation (`.`) to access variables from the current chain state (initial `chain.variables` + `extract`ed values + env vars). Example: `{{.UserID}}`, `{{.AuthToken}}`, `{{.HOSTNAME}}`.
*   **Built-in Variables/Functions:** Standard Go `text/template` functions are available. Consult Go documentation for available functions. Environment variables present when `api-tool` starts are automatically included in the initial state.
*   **Missing Keys Error:** Because `Option("missingkey=error")` is used, referencing a non-existent variable in a template (`{{.NonExistentVar}}`) will cause the step to fail immediately. This helps catch typos and logic errors early.
*   **Templating Targets:** Use templating in: endpoint `path` definitions, step header values (`request.headers`), step request bodies (`request.data`), file paths (`request.upload_body_from`, `request.file_fields`, `request.download_to`), filter inputs (`filter.input`), filter JQ expressions (`filter.jq`), filter step extraction templates (`extract` under `filter`), and the final output file path (`output.file`).
*   **State Type:** Remember that state variables, even if extracted from numbers or booleans in JSON, are stored and templated as *strings*. If you need to treat them numerically or embed them without quotes in a JSON template, use JQ in a `filter` step for conversion or construct the JSON carefully.

## 7. Building Effective Chains

*   **Define Initial State:** Use `chain.variables` for static configuration values specific to the playbook run, or values derived from the environment before the chain starts.
    ```yaml
    chain:
      variables:
        TARGET_ENV: "production"
        REPORT_TYPE: "daily"
    ```
*   **Data Flow is Key:** Think about what data each step needs and what data it produces.
    *   Use `extract` to capture necessary outputs (IDs, tokens, status codes, specific data fields, file paths).
    *   Use templates in subsequent steps to consume these extracted values.
*   **Break Down Complexity:** Decompose large tasks into smaller, logical steps. Use the `name` field for clarity in logs.
    ```yaml
    steps:
      - name: authenticate_and_get_token
        request:
          # ... request to auth endpoint ...
        extract:
          ACCESS_TOKEN: ".access_token" # Extract token from response body

      - name: list_pending_items
        request:
          api: data_service
          endpoint: list_items
          headers:
            Authorization: "Bearer {{.ACCESS_TOKEN}}" # Use extracted token
        extract:
          # Get comma-separated list of IDs using jq map and join
          PENDING_IDS: ".items[].id | @csv" # Produces CSV, need further processing if used directly

      - name: process_first_item # Example: requires external script or more jq logic
        # ... processing logic outside simple templating ...
    ```
*   **Use `filter` for Intermediate Processing:** If you need to transform or reshape data *before* using it in the next API call (beyond simple extraction), use a `filter` step with `jq`.
    ```yaml
    steps:
      - name: get_raw_user_data
        request: # ... fetch user ...
        extract:
          RAW_USER_JSON: "."

      - name: transform_user_data_for_update
        filter:
          input: '{{.RAW_USER_JSON}}'
          # Use JQ to reshape the data and select fields
          jq: '{firstName: .profile.givenName, lastName: .profile.familyName, status: .account.state}'
        extract:
          PATCH_PAYLOAD: "{{result}}" # Capture the transformed JSON string

      - name: update_user_record
        request:
          method: "PATCH"
          data: "{{.PATCH_PAYLOAD}}" # Use the transformed data
          # ... other request details ...
    ```

## 8. Handling Pagination

*   **Choose the Right Type:** Select `offset`, `page`, `cursor`, or `link_header` based on the API's mechanism.
*   **Verify Parameters:** Double-check `results_field`, `limit`, `offset_param`/`page_param`, `next_field`/`next_header`, etc., against the API documentation. An incorrect `results_field` JQ path is a common error.
*   **`param_location: body`:** Only works for methods allowing a request body (POST, PUT, PATCH, sometimes DELETE). Ensure `body_path` points to the correct place within the JSON structure (e.g., `"query.options"`). Invalid paths will cause errors.
*   **`force_initial_pagination_params`:** Set this to `true` on an offset/page endpoint if the *first* call to the API *requires* the initial limit/offset or page/size parameters (e.g., `offset=0&limit=10`). If false (default), these params are only added *after* the first page is fetched.
*   **`max_pages`:** Use this as a safety net to prevent accidental infinite loops, especially during development or if the API's termination condition is unclear.
*   **Aggregation:** Remember `api-tool` aggregates paginated results into a single final JSON *string* (usually an array). If dealing with extremely large datasets where memory is a concern, consider using `max_pages` to process in batches, processing the output externally, or using `download_to` if appropriate (though `download_to` prevents pagination).

## 9. Leveraging JQ

*   **External Dependency:** `jq` must be installed separately and available in the system `PATH` where `api-tool` runs. This is crucial in containerized environments.
*   **Extraction Power:** JQ filters in `extract` (for `request` steps) are excellent for precisely selecting data from JSON response bodies.
    *   Simple: `"VarName": ".fieldName"`
    *   Nested: `"VarName": ".data.attributes.value"`
    *   Arrays: `"FirstID": ".[0].id"`, `"AllNames": ".users[].name | join(\",\")"`
    *   Complex: `"ActiveUserCount": ".users | map(select(.isActive)) | length"`
*   **Filter Steps:** Use `filter` steps for more complex transformations than simple extraction allows, or when you need to manipulate data *between* steps based on the state *before* the next API call.
    *   Input via template: `input: "{{.PREVIOUS_STEP_RESULT_JSON}}"`
    *   JQ filter via template: `jq: ".items | map({id: .key, value: .val}) | select(.value > {{.THRESHOLD}})"`
    *   Capture output: `extract: { TRANSFORMED_DATA: "{{result}}" }` or use template: `extract: { MESSAGE: "Processed {{.result | length}} items." }`
*   **Raw Output (`-r`):** `api-tool` uses `jq -r` implicitly for extraction to get raw string values. Be mindful of this if your filter produces JSON structures – they will be stringified. Use `filter` steps if you need to pass structured JSON between steps (by extracting the stringified JSON and using it as input to the next filter/template).

## 10. File Operations

*   **Choose the Right Upload:**
    *   `upload_body_from`: For sending the raw content of a single file as the *entire* request body (e.g., PUTing a binary firmware file). `Content-Type` defaults to `application/octet-stream` unless overridden in headers. Not recommended for GET.
    *   `form_data` + `file_fields`: For standard `multipart/form-data` uploads (e.g., submitting a web form with file attachments). `api-tool` sets the `Content-Type: multipart/form-data; boundary=...`. Use with POST/PUT/PATCH.
*   **Dynamic Paths:** Use templates and environment variables for file paths in `upload_body_from`, `file_fields`, and `download_to` to make them dynamic based on state or environment variables.
    ```yaml
    # Download to a path based on extracted ID and date variable
    download_to: "/data/downloads/{{.ITEM_ID}}_{{.REPORT_DATE}}.pdf"

    # Upload a specific file based on state
    file_fields:
      reportFile: "/reports/{{.REPORT_TYPE}}/{{.FILENAME}}"
    ```
*   **`download_to` Limitation:** Remember that using `download_to` in a `request` step prevents extracting data from the response *body* using JQ in the *same* step's `extract` block. Header extraction (`header:...`) is still possible. If you need both the file and body content, you might need two separate requests (if feasible) or process the downloaded file afterwards. Not recommended for POST/PUT.

## 11. Debugging Playbooks

*   **Increase Log Level:** Use `-loglevel debug`. This shows detailed information about request/response headers, bodies (snippets), state changes, template rendering attempts, pagination steps, etc.
*   **Inspect State:** Add temporary `filter` steps to print the current state or specific variables to the log.
    ```yaml
    # Temporary debug step
    - name: DEBUG_show_state_before_update
      filter:
        input: '{{.}}' # Pass the whole state map as JSON
        jq: '.' # Just print the input JSON (the state)
      # No extract needed, just observe log output
    ```
*   **Test Incrementally:** Build and test your chain one step at a time. Verify extraction and templating work as expected before adding the next step. Use `-loglevel debug`.
*   **Check `jq` Separately:** If a `filter` or JQ `extract` fails, test the JQ filter directly against a sample JSON input using the `jq` command line tool to isolate the issue.
*   **Validate Configuration:** Use a YAML validator to check for syntax errors in `config.yaml`. `api-tool`'s internal validation catches many structural and logical errors on startup.
*   **Network Issues:** Use `debug` logging to see connection errors, timeouts, or unexpected HTTP status codes. Check TLS verification (`tls_skip_verify` - use cautiously!). Check retry logic (`retry` config, `exclude_errors`). Check API timeouts (`TimeoutSeconds`).

## 12. Advanced Techniques & Gotchas

*   **Simulating Conditionals:** `api-tool` lacks native `if/then/else` *between steps*. Workarounds:
    *   **Template Failure:** Design templates that fail (due to `missingkey=error`) if a required variable isn't present, halting the chain. Relies on specific variable presence/absence.
    *   **JQ Logic:** Use `filter` steps with JQ to produce specific outputs (e.g., "true"/"false", different data structures, or even empty strings) based on input state. Subsequent steps can then template based on these specific outputs, potentially skipping actions if a value is empty (though the step itself runs). This can become complex.
    *   **External Scripting:** For complex logic, use `api-tool` for API interactions and orchestrate the calls from a shell script, Python, etc., that handles the conditional logic, potentially running `api-tool` multiple times with different parameters or configurations.
*   **No Looping (Except Pagination):** You cannot define loops within the chain structure itself (e.g., "for each ID in this list, run step X"). Pagination handles looping over *pages*, not arbitrary data lists. Workarounds:
    *   Process only the first item found (e.g., extract `.[0].id`).
    *   Use JQ to aggregate data in a way that a single subsequent API call can handle (if the API supports batch operations).
    *   Use external scripting to loop and call `api-tool` repeatedly, passing the current item via environment variables or initial `chain.variables` (less ideal).
*   **State is String-Based:** Values extracted and stored in the state are generally treated as strings. If you extract `{"count": 5}` using `.` JQ filter, the state variable holds the *string* `{"count": 5}`. When templating this back into a JSON payload (`data: "{{.MyJsonString}}"`), it will be inserted as a string. Use `jq` in a `filter` step if you need to manipulate the structure or convert types before the next step.
*   **Rate Limiting:** `api-tool`'s retry logic helps with transient errors but doesn't explicitly handle API rate limits (e.g., 429 Too Many Requests). The **fixed** backoff might not be ideal for rate limits. If you hit rate limits frequently, consider:
    *   Adding 429 to `exclude_errors` and handling it externally.
    *   Increasing `backoff_seconds` significantly.
    *   Adding delays via external scripting.
*   **Large Data Handling:** Aggregating many pages of large responses in memory can be demanding. `download_to` streams the response directly to a file, avoiding high memory use for that specific step's body. Consider processing large datasets in chunks using `max_pages` or external scripting.

## 13. Limitations

*   **No Native Conditionals/Branching:** Steps execute sequentially. No built-in `if/else` logic *between* steps.
*   **No Native Looping:** Cannot loop over arbitrary lists/data within the chain structure.
*   **Simple String-Based State:** State variables are key-value strings; complex structures require JQ filtering/manipulation.
*   **External `jq` Dependency:** Requires `jq` to be installed and in PATH for `filter` steps and JQ-based `extract`.
*   **Basic Error Handling:** Retries on failures based on config, but no sophisticated error branching or custom error handling steps within the chain. Chains typically fail fast on unrecoverable errors or exhausted retries.
*   **Sequential Execution:** Steps run one after another; no built-in parallelism.
*   **Templating Scope:** Go `text/template` is powerful but less feature-rich than templating engines like Jinja2 for complex logic or control structures within the template itself.

## 14. Example Playbooks

**(Example 1: OAuth2 Auth -> Fetch Paginated Users -> Extract First Admin ID)**

```yaml
# config.yaml
retry: { max_attempts: 3, backoff_seconds: 2 }
auth:
  credentials:
    client_id: "$OAUTH_CLIENT_ID"
    client_secret: "$OAUTH_CLIENT_SECRET"
    token_url: "https://auth.example.com/token"
logging: { level: "info" }
apis:
  user_service:
    base_url: "https://api.example.com/v1"
    auth_type: "oauth2" # Handles token fetch/refresh
    endpoints:
      list_users:
        path: "/users"
        method: "GET"
        pagination:
          type: "offset"
          results_field: "data"
          limit: 50
          offset_param: "offset"
          limit_param: "limit"
          total_field: "meta.total"
      get_user:
         path: "/users" # Will append ID later
         method: "GET"

chain:
  variables:
    ADMIN_ROLE: "administrator"
  steps:
    - name: list_all_users
      request:
        api: "user_service"
        endpoint: "list_users"
        # Auth and pagination handled automatically by config
      extract:
        # Get the full JSON array string of all users across pages
        ALL_USERS_JSON: "."

    - name: find_first_admin_id
      filter:
        input: '{{.ALL_USERS_JSON}}'
        # Use JQ to find the first user with the target role
        jq: '[ .[] | select(.role == "{{.ADMIN_ROLE}}") ] | .[0].id'
      extract:
        # Capture the ID (or null if none found)
        FIRST_ADMIN_ID: "{{result}}"

  output:
    file: "first_admin_id.txt"
    var: "FIRST_ADMIN_ID" # Write the found ID to a file
```

**(Example 2: Post Data -> Extract Location Header -> Download Created Resource)**

```yaml
# config.yaml
retry: { max_attempts: 2, backoff_seconds: 1 }
auth: { default: "bearer" } # Assumes API_TOKEN env var
logging: { level: "debug" }
apis:
  resource_api:
    base_url: "https://resources.example.com/api"
    auth_type: "bearer"
    endpoints:
      create_resource:
        path: "/resources"
        method: "POST"
      get_resource: # Generic GET, path determined dynamically
        # This endpoint's path is unused if overridden in step
        path: "/should_be_overridden"
        method: "GET"

chain:
  variables:
    RESOURCE_NAME: "MyNewGadget-{{.HOSTNAME}}"
    RESOURCE_TYPE: "gadget"
  steps:
    - name: create_new_resource
      request:
        api: "resource_api"
        endpoint: "create_resource"
        headers:
          Content-Type: "application/json"
          Accept: "application/json"
        data: |
          {
            "name": "{{.RESOURCE_NAME}}",
            "type": "{{.RESOURCE_TYPE}}"
          }
      extract:
        # Extract the URL of the new resource from the Location header
        # Regex captures everything after 'Location: '
        NEW_RESOURCE_URL: "header:Location:(.*)"

    - name: download_created_resource
      request:
        api: "resource_api"
        # Specify the endpoint, but its 'path' isn't used directly here
        # because we construct the full URL in the template below.
        endpoint: "get_resource"
        # Build the URL for the GET request using the extracted Location header.
        # NOTE: Templating on the 'path' defined in the *endpoint* config is preferred.
        # This example shows overriding the path completely if needed.
        # Assumes NEW_RESOURCE_URL is absolute or resolveable vs base_url.
        # This requires manual URL construction, less ideal than path templating.
        # We'll pretend a `url_override_template` exists for this example:
        url_override_template: "{{.NEW_RESOURCE_URL}}"
        method: "GET" # Ensure GET method
        headers:
          Accept: "application/octet-stream" # Ask for binary data
        # Download the response body
        download_to: "/downloads/{{.RESOURCE_NAME}}.bin"
      extract:
        # Can still extract other headers if needed
        RESOURCE_ETAG: "header:ETag:(.*)"

  output:
    file: "/downloads/{{.RESOURCE_NAME}}.etag"
    var: "RESOURCE_ETAG"
```

**(Example 3: Multipart File Upload (Chain))**

```yaml
# config.yaml
retry: { max_attempts: 3, backoff_seconds: 5 }
auth: { default: "api_key", credentials: { api_key: "%REPORTS_API_KEY%" } }
logging: { level: "info" }
apis:
  reporting:
    base_url: "https://reports.example.com"
    auth_type: "api_key" # Auth handled by client
    endpoints:
      upload:
        path: "/upload/sales"
        method: "POST"
chain:
  variables:
    REPORT_DATE: "2025-03-31" # Could be dynamic
    UPLOAD_USER: "%USERNAME%"
  steps:
    - name: upload_sales_report
      request:
        api: "reporting"
        endpoint: "upload"
        # Method POST inherited
        form_data: # Regular form fields
          reportDate: "{{.REPORT_DATE}}"
          uploadedBy: "{{.UPLOAD_USER}}"
          comments: "Daily sales data"
        file_fields: # Files to include
          # Form field name -> Local file path
          salesData: "$REPORT_PATH" # Use environment variable for path
          meta: "/config/upload_metadata.json" # Another static file
      # No extract needed, just check logs/server for success
```

**(Example 4: Download Binary File (Chain))**

```yaml
# config.yaml
retry: { max_attempts: 2, backoff_seconds: 10 }
auth: { default: "none" }
logging: { level: "info" }
apis:
  device_firmware:
    base_url: "https://firmware.devices.com"
    endpoints:
      get_latest:
        path: "/firmware/model-xyz/latest"
        method: "GET"
chain:
  variables:
    MODEL: "model-xyz"
    DOWNLOAD_DIR: "/opt/firmware_updates"
  steps:
    - name: download_firmware
      request:
        api: "device_firmware"
        endpoint: "get_latest" # GET method inherited
        headers:
          Accept: "application/octet-stream"
        # Save the response body directly to a file
        download_to: "{{.DOWNLOAD_DIR}}/{{.MODEL}}_latest.bin"
      extract:
        # Can still extract headers while downloading
        FW_VERSION: "header:X-Firmware-Version:(.*)"
        FW_ETAG: "header:ETag:(.*)"
  output: # Example: Write ETag to a separate file
    file: "{{.DOWNLOAD_DIR}}/{{.MODEL}}_latest.etag"
    var: "FW_ETAG"
```

**(Example 5: Complex Chain - Get ID, Fetch Details, Filter, Post Update)**

```yaml
# config.yaml snippet
retry: { max_attempts: 3, backoff_seconds: 2 }
auth: { default: "bearer" } # Use API_TOKEN env var
logging: { level: "debug" }
apis:
  task_api:
    base_url: "https://tasks.internal.co/api"
    auth_type: "bearer"
    endpoints:
      find_pending:
        path: "/tasks?status=pending&limit=1&sort=created:desc"
        method: "GET"
        pagination: { type: "none" } # Ensure no pagination if API doesn't support it well here
      get_task:
        # Path includes template variable {{.PENDING_TASK_ID}}
        # This template is rendered *during chain execution* using current state.
        path: "/tasks/{{.PENDING_TASK_ID}}"
        method: "GET"
      update_task:
        path: "/tasks/{{.PENDING_TASK_ID}}" # Template used here too
        method: "PATCH" # Use PATCH for partial update

chain:
  variables: {}
  steps:
    # Step 1: Find the latest pending task ID
    - name: find_latest_pending
      request:
        api: "task_api"
        endpoint: "find_pending"
      extract:
        PENDING_TASK_ID: ".[0].id" # Assumes response is array: [{"id": "...", ...}]
        TASK_COUNT: ". | length" # Get number of pending tasks found

    # Step 2: Fetch full details using the templated path from endpoint config
    - name: get_task_details
      request:
        api: "task_api"
        endpoint: "get_task" # The path template "/tasks/{{.PENDING_TASK_ID}}" will be rendered now
        method: "GET"
      extract:
        TASK_DETAILS_JSON: "." # Get the full task JSON

    # Step 3: Use JQ filter step to extract a specific field
    - name: filter_task_data
      filter:
        input: "{{.TASK_DETAILS_JSON}}"
        jq: ".priority" # Extract priority field
      extract:
        TASK_PRIORITY: "{{result}}" # Assign JQ output to variable

    # Step 4: Update the task status using the templated path and data
    - name: mark_task_processing
      request:
        api: "task_api"
        endpoint: "update_task" # Path template "/tasks/{{.PENDING_TASK_ID}}" rendered
        method: "PATCH"
        headers:
          Content-Type: "application/merge-patch+json" # Example specific content type
        data: | # Send only the fields to update
          {
            "status": "processing",
            "processedBy": "api-tool-{{.HOSTNAME}}",
            "priorityEcho": {{.TASK_PRIORITY}} # Use extracted priority (as string)
          }
      # No extraction needed, check logs or subsequent requests
```
**Explanation for Playbook 5:**
This chain demonstrates multiple steps and data passing:
1.  Fetches the latest pending task and extracts its ID (`PENDING_TASK_ID`).
2.  Uses the `get_task` endpoint. The `path` defined for this endpoint (`/tasks/{{.PENDING_TASK_ID}}`) is rendered using the current state, dynamically constructing the correct URL. Stores the full JSON response in `TASK_DETAILS_JSON`.
3.  Uses a local `filter` step with `jq` to extract the `.priority` field from the stored `TASK_DETAILS_JSON` into `TASK_PRIORITY`.
4.  Uses the `update_task` endpoint (which also uses the `PENDING_TASK_ID` in its path template) and the `TASK_PRIORITY` in the `data` template to send a PATCH request, updating the task's status.

