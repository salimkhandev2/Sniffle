# Sniffle

A local HTTP(S) inspector with intercept, rules, scope, and advanced analysis capabilities.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
mitmdump -s main.py -p 8080
```

Then open the URL printed in the terminal (it contains a private token).

## Features

### Core Features
- **Live Traffic Inspection**: View HTTP(S) requests and responses in real-time
- **Request Editing**: Edit method, URL, headers, and body before resending
- **Response Comparison**: Compare original and edited responses side-by-side
- **Filtering**: Filter requests by host, path, status, or body content
- **Copy Functions**: Copy request/response as JSON, cURL, or raw text

### Advanced Features

#### Intercept Mode
- Pause incoming requests for inspection
- Forward, drop, or modify requests before they reach their destination
- Toggle intercept mode with the "Intercept" button

#### Rules System
- Create rules to automatically modify or drop matching requests
- Rule types:
  - `drop`: Block matching requests
  - `modify_header`: Add/modify request headers
  - `modify_body`: Replace request body
- Match by method, URL pattern, or host pattern

#### Scope
- Limit traffic capture to specific domains
- Reduces noise when debugging specific services

#### System Proxy Toggle (Windows)
- Enable/disable system proxy directly from the UI
- Automatically sets proxy to `127.0.0.1:8080` when enabled
- Requires administrator privileges

#### HAR Import/Export
- Export captured traffic as HAR files
- Import HAR files from other tools (Charles, Fiddler, etc.)

### Analysis Tools

#### Diff View (DeepDiff)
- Compare original and edited responses
- Shows exactly what changed between responses
- Access via "Diff" button in request editor

#### JWT Tool (PyJWT)
- Decode JWT tokens from headers or response bodies
- Edit JWT claims and re-sign tokens
- Supports multiple algorithms (HS256, HS384, HS512)
- Access via "JWT" button in request editor or response viewer

#### Secrets Detection (detect-secrets)
- Automatically scans captured traffic for API keys, tokens, and passwords
- Shows 🔐 badge on requests containing secrets
- Helps identify leaked credentials in real-time

#### Security Scanning (Nuclei)
- Scan requests for known vulnerabilities using Nuclei templates
- Requires Nuclei to be installed separately
- Access via "Scan" button in response viewer
- Install Nuclei from: https://github.com/projectdiscovery/nuclei

#### OpenAPI Import (Schemathesis)
- Import OpenAPI/GraphQL specifications
- Auto-generate test requests from API specs
- Explore API endpoints directly from the UI
- Access via "OpenAPI" button in header

## Security

- UI binds to `127.0.0.1` only
- Token-based authentication for API access
- Host-header validation prevents DNS rebinding
- Content rendered as plain text (no script execution)

## Environment Variables

- `SNIFFLE_UI_PORT`: UI server port (default: 8081)
- `SNIFFLE_PROXY_PORT`: Proxy port for system proxy toggle (default: 8080)

## Development

This project uses Python 3 with mitmproxy and additional analysis libraries.
