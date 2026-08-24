# proxy-router

Small host-based reverse proxy for routing requests to Proxmox VMs.

## Features

- Routes traffic by incoming `Host` header
- Proxies to VM targets defined in a JSON config file
- Includes a simple `/healthz` endpoint
- Uses only the Go standard library

## Configuration

Create a `routes.json` file:

```json
{
  "routes": [
    {
      "host": "proxmox-vm.local",
      "target": "http://192.168.1.50:8006"
    }
  ]
}
```

You can also copy `/home/runner/work/proxy-router/proxy-router/routes.example.json`.

## Run

```bash
go run .
```

Environment variables:

- `LISTEN_ADDR` (default `:8080`)
- `CONFIG_PATH` (default `routes.json`)

## Test

```bash
go test ./...
```
