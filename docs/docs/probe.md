# Probe

The `webscan probe` family of commands provides techniques to probe various types of web services looking for misconfigurations, vulnerabilities, and exposed information that is useful to security teams.

## Webserver

### Usage

```bash
webscan probe webserver --targets https://example.com,https://anotherexample.dev
```

### Help Text

```bash
webscan probe webserver -h
Perform a web probe against targets to identify existence of web servers

Usage:
  webscan probe webserver [flags]

Flags:
  -h, --help             help for webserver
      --targets string   Address targets to perform webserver probing agains, comma delimited list

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
