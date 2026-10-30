# Using the NSX MCP server

Run commands below from `nsxt-mcp/`. Replace example hostnames, IDs and absolute
paths. `uv sync --locked` installs the pinned project environment. The examples
contain placeholders only and do not contact anything until you run a client.

## 1. Choose the credential flow

| Use case | Server configuration | Credentials |
|---|---|---|
| Local stdio, shared service account | `shared.json` | `NSXT_SERVICE_USER` / `NSXT_SERVICE_PASSWORD` loaded from a private env file |
| Local stdio, shared password file | `shared-password-file.json` | Username environment reference; password is read from `password_file` |
| Local stdio, own account | `per-user.json` | `NSXT_USER` / `NSXT_PASSWORD` loaded from a private env file |
| Remote HTTP, shared execution | `remote-shared.json` on server | Caller uses own NSX/LDAP account; server separately loads service-account secrets |
| Remote HTTP, per-user execution | `remote-per-user.json` on server | Caller uses own NSX/LDAP account for admission and operational reads |

Local accounts use a local username, such as `reader`. LDAP accounts use the name
accepted by NSX Manager, such as `operator@example.test`. The MCP server does not
bind directly to LDAP. Remote grants use NSX's returned canonical username.

## 2. Local stdio with a private credentials file

Create a **new private configuration directory**, then copy the chosen templates.
For example, for a shared account:

```sh
install -d -m 700 "$HOME/.config/nsxt-mcp"
install -m 600 examples/shared.env.example "$HOME/.config/nsxt-mcp/shared.env"
install -m 600 examples/shared.json "$HOME/.config/nsxt-mcp/config.json"
```

Edit `config.json`, replacing the synthetic manager URL with your Manager VIP/FQDN.
For a private NSX CA, add `"ca_bundle": "/absolute/path/to/nsx-ca.pem"` to each target.
Edit `shared.env` with the real account credentials:

```dotenv
NSXT_SERVICE_USER='reader@example.test'
NSXT_SERVICE_PASSWORD='your-password-here'
```

This is a **dotenv file**, not a shell script: do not add `export` or source it.
The examples load it using uv's `--env-file`. Environment/file paths are server-side
settings, not MCP tool arguments. Keep the private file outside the repository.

Start the server through a client; the example client launches its stdio subprocess:

```sh
uv run --env-file "$HOME/.config/nsxt-mcp/shared.env" \
  python examples/mcp_client.py stdio \
  --config "$HOME/.config/nsxt-mcp/config.json"
```

The default tool lists your configured target aliases. To read a version:

```sh
uv run --env-file "$HOME/.config/nsxt-mcp/shared.env" \
  python examples/mcp_client.py stdio \
  --config "$HOME/.config/nsxt-mcp/config.json" \
  --tool nsx_get_version --arguments '{"target":"site-a"}'
```

For a per-user stdio process, use `per-user.json` and `per-user.env.example` instead:

```dotenv
NSXT_USER='operator@example.test'
NSXT_PASSWORD='your-password-here'
```

Use the same client command with that env file and configuration. Each user runs
an isolated process. The server command alone (`uv run ... nsxt-mcp --config ...`)
waits for MCP protocol messages; it is not an interactive natural-language shell.

## 3. Shared credentials using a standalone password file

Copy `shared-password-file.json` to your private config directory and edit its
absolute CA/password-file paths. Its credential section is:

```json
{
  "credential_profiles": {
    "network-reader": {
      "username_env": "NSXT_SERVICE_USER",
      "password_file": "/absolute/path/to/secrets/nsx-reader.password"
    }
  }
}
```

The password file contains **only the password**, without `PASSWORD=`, surrounding
quotes or JSON. An editor's trailing newline is removed; spaces inside the password
are preserved. Set file permissions to `600`, or `400` if no edits are needed.
Put only the username in the private env file:

```dotenv
NSXT_SERVICE_USER='reader@example.test'
```

Specify **one** of `password_file` or `password_env` in a credential profile, never
both. Different targets can reference different profiles. Relative secret/CA paths
are relative to the server process working directory; absolute paths are recommended.

For Podman, use **container paths** in JSON, for example
`/config/secrets/nsx-reader.password`, and mount the corresponding host directory
read-only at `/config`. Runtime UID 1001 must be able to read those files.

## 4. Connect an MCP host / assistant

`mcp-host-stdio.json` is a conventional `mcpServers` stdio configuration. Replace
all absolute paths, including the path to `uv`, and copy the entry into the MCP
configuration supported by your host. It invokes uv with `--env-file`, so passwords
do not need to be embedded in the host's JSON configuration.

`mcp-host-podman.json` launches the packaged image using `podman run --rm -i`.
It mounts configuration at `/config` and loads credentials through `--env-file`.
Paths in the mounted NSX JSON must therefore use `/config/...`. Do not add `-t`:
stdio protocol traffic must not run through a pseudo-terminal.

After connecting, try prompts such as:

- “List the configured NSX targets, then show the version of site-a.”
- “On site-a, list Gateway Firewall policies in the default domain. Show the
  ordered rules for policy `<actual-policy-id>`, including disabled state and scope.”
- “On site-a, list Tier-0 gateways and their locale services. Ask me which Edge
  to inspect before requesting BGP runtime status.”
- “Read Manager status for site-a and site-b. Report individual failures and do
  not equate a successful read with a healthy cluster.”

Host-specific remote configuration formats vary. The verified remote example
below uses FastMCP's Python client with Basic authentication. A remote host must
support custom Basic credentials/headers; an OAuth-only setup is not interchangeable.

## 5. Remote HTTPS client

The administrator first runs the server using `remote-shared.json` or
`remote-per-user.json` and the TLS flags documented in `../RUNBOOK.md`.
For shared execution, the caller must have an explicit target/tool-group grant.
Server service-account credentials are **not** distributed to callers.

Copy `remote-client.env.example` to a private file and set the caller credentials:

```dotenv
MCP_USERNAME='operator@example.test'
MCP_PASSWORD='your-password-here'
```

```sh
uv run --env-file "$HOME/.config/nsxt-mcp/remote-client.env" \
  python examples/mcp_client.py remote \
  --url https://mcp.example.test:8443/mcp \
  --ca-bundle /absolute/path/to/mcp-server-ca.pem \
  --tool nsx_get_cluster_health --arguments '{"target":"site-a"}'
```

Here `--ca-bundle` verifies the **remote MCP listener**. The NSX CA stays in the
server's target configuration. Omit the client flag when the MCP listener is
already trusted by system CAs. The client never disables TLS verification or
uses ambient HTTP proxies.

Alternatively, keep only `MCP_USERNAME` in the env file and pass
`--password-file /absolute/path/to/my-password`. This file has the same plain-text
password-only format described above. Passwords are not accepted as CLI values.
The same remote client works with both execution modes; the server chooses the mode.

## 6. Explicit pagination and output handling

Server-side pagination is already bounded by `max_pages`, `max_items`,
`max_response_bytes` and the tool deadline. A tool can therefore return:

```json
{
  "items": [{"id":"example-rule"}],
  "complete": false,
  "next_cursor": "opaque-cursor-from-nsx",
  "pages": 1
}
```

That is a valid but incomplete collection. The example client can continue it:

```sh
uv run --env-file "$HOME/.config/nsxt-mcp/shared.env" \
  python examples/mcp_client.py stdio \
  --config "$HOME/.config/nsxt-mcp/config.json" \
  --tool nsx_list_gateway_firewall_rules \
  --arguments '{"target":"site-a","domain_id":"default","policy_id":"actual-policy-id","page_size":100}' \
  --max-calls 10
```

`--max-calls` bounds **MCP calls**, not NSX pages. Each call may traverse multiple
NSX pages. The client retains each response's metadata under `responses`, detects
non-advancing cursors, and returns the final `complete`/`next_cursor`. If still
incomplete after the call cap, resume using that cursor with the **same tool,
target, filters, scope and identity**. Never edit or decode opaque cursors.

The client continues only `items` collections with `next_cursor`. It does not
invent cursor parameters for statistics observations or retry partial fleet results
as if they were pages. Tool failures are raised instead of being printed as a
successful empty list. Progress is written to stderr only when it is a terminal;
stdout is JSON and can be redirected to a report file.

## 7. Other useful tool calls

Use the same connection command and substitute `--tool` / `--arguments`:

```json
{"tool":"nsx_list_gateways","arguments":{"target":"site-a","gateway_type":"tier-0s"}}
```

```json
{"tool":"nsx_get_bgp_neighbor_status","arguments":{"target":"site-a","tier0_id":"actual-tier0-id","locale_service_id":"actual-locale-id","enforcement_point_path":"/infra/sites/default/enforcement-points/default","edge_path":"/infra/sites/default/enforcement-points/default/edge-clusters/actual-cluster-id/edge-nodes/actual-edge-id"}}
```

```json
{"tool":"nsx_get_fleet_health","arguments":{"targets":["site-a","site-b"]}}
```

These objects show the tool name and arguments separately; the CLI accepts the
arguments object in `--arguments`, not the entire wrapper. All calls are read-only.
See `../TEST_COVERAGE.md` for tested corner cases and output-validation boundaries.
