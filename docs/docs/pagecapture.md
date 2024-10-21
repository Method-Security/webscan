# Pagecapture

The `webscan pagecapture` command collects the HTML or screenshots from a specified URL target.

## Usage

```bash
webscan pagecapture [command]
```

## Commmands

### HTML Request

#### Usage

```bash
webscan pagecapture html request --target https://example.com
```

#### Help Text

```bash
Perform a webpage HTML capture using a basic HTTP/HTTPS request

Usage:
  webscan pagecapture html request [flags]

Flags:
  -h, --help       help for request
      --insecure   Allow insecure connections

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --target string        URL target to perform webpage capture
      --timeout int          Timeout in seconds for the capture (default 30)
  -v, --verbose              Verbose output
```

### HTML Browser

#### Usage

```bash
webscan pagecapture html browser --target https://example.com
```

#### Help Text

```bash
Perform a fully rendered webpage HTML capture using a headless browser

Usage:
  webscan pagecapture html browser [flags]

Flags:
  -h, --help   help for browser

Global Flags:
  --minDOMStabalizeTime int   Minimum time in seconds to wait for DOM to stabilize, currently only used in screenshots (default 5)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --target string        URL target to perform webpage capture
      --timeout int          Timeout in seconds for the capture (default 30)
  -v, --verbose              Verbose output
```

### HTML Browserbase

#### Usage

```bash
webscan pagecapture html browserbase --target https://example.com
```

#### Help Text

```bash
Perform a fully rendered webpage HTML capture using Browserbase. Useful for avoiding bot detection or maintaining stealth

Usage:
  webscan pagecapture html browserbase [flags]

Flags:
      --country stringArray   List of countries to use for the proxy
  -h, --help                  help for browserbase
      --project string        Browserbase project ID
      --proxy                 Instruct Browserbase to use a proxy
      --token string          Browserbase API token

Global Flags:
  --minDOMStabalizeTime int   Minimum time in seconds to wait for DOM to stabilize, currently only used in screenshots (default 5)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --target string        URL target to perform webpage capture
      --timeout int          Timeout in seconds for the capture (default 30)
  -v, --verbose              Verbose output
```

### Screenshot Browser

#### Usage

```bash
webscan pagecapture screenshot browser --target https://example.com
```

#### Help Text

```bash
Perform a fully rendered webpage screenshot and HTML capture using a headless browser

Usage:
  webscan pagecapture screenshot browser [flags]

Flags:
      --browserPath string   Path to a browser executable
  -h, --help                 help for browser

Global Flags:
  --minDOMStabalizeTime int   Minimum time in seconds to wait for DOM to stabilize, currently only used in screenshots (default 5)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --target string        URL target to perform webpage capture
      --timeout int          Timeout in seconds for the capture (default 30)
  -v, --verbose              Verbose output
```

### Screenshot Browserbase

#### Usage

```bash
webscan pagecapture screenshot browser --target https://example.com
```

#### Help Text

```bash
Perform a fully rendered webpage screenshot and HTML capture using Browserbase. Useful for avoiding bot detection or maintaining stealth

Usage:
  webscan pagecapture screenshot browserbase [flags]

Flags:
      --country stringArray   List of countries to use for the proxy
  -h, --help                  help for browserbase
      --project string        Browserbase project ID
      --proxy                 Instruct Browserbase to use a proxy
      --token string          Browserbase API token

Global Flags:
  --minDOMStabalizeTime int   Minimum time in seconds to wait for DOM to stabilize, currently only used in screenshots (default 5)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --target string        URL target to perform webpage capture
      --timeout int          Timeout in seconds for the capture (default 30)
  -v, --verbose              Verbose output
```