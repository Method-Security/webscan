# Subdomain Takeover

The `webscan sdt` family of commands provides techniques to scan various types of web services looking for Subdomain Takeovers.
## Webserver

### Usage

```bash
webscan sdt --target https://example.com
```

### Help Text

```bash
webscan sdt -h
Perform validation of URL target for potential subdomain takeover

Usage:
  webscan sdt [flags]

Flags:
      --concurrency int   Number of concurrent checks (default 10)
  -h, --help              help for sdt
      --hide_fails        Don't display failed results
      --https             Force https protocol if not no protocol defined for target (default false)
      --target string     Comma separated list of domains
      --targets string    File containing the list of subdomains
      --timeout int       Request timeout in seconds (default 10)
      --verify_ssl        If set to true it won't check sites with insecure SSL and return HTTP Error
      --vuln              Save only vulnerable subdomains

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
