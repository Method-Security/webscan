# Routecapture

The `webscan routecapture` command all web routes and URLs from a specified target. It uses the same underlying techniques that `pagecapture` uses to render HTML.

## Usage

```bash
webscan pagecapture [command]
```

## Commmands

### Request

#### Usage

```bash
webscan routecapture request --target https://example.com
```

#### Help Text

```bash
Perform a webpage HTML capture using a basic HTTP/HTTPS request

Usage:
  webscan routecapture request [flags]

Flags:
  -h, --help       help for request
      --insecure   Allow insecure connections

Global Flags:
      --base-urls-only       Only match routes and urls that share the base URLs domain (default true)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --target string        URL target to perform webpage capture
      --timeout int          Timeout in seconds for the capture (default 30)
  -v, --verbose              Verbose output
```

### Browser

#### Usage

```bash
webscan routecapture browser --target https://example.com
```

#### Help Text

```bash
Perform a webpage HTML capture using a headless browser

Usage:
  webscan routecapture browser [flags]

Flags:
  -h, --help   help for browser

Global Flags:
      --base-urls-only       Only match routes and urls that share the base URLs domain (default true)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --target string        URL target to perform webpage capture
      --timeout int          Timeout in seconds for the capture (default 30)
  -v, --verbose              Verbose output
```