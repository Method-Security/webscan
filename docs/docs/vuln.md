# Vuln

The `webscan vuln` command leverages Project Discovery's [nuclei](https://github.com/projectdiscovery/nuclei/) capability to perform vulnerability scans against the provided target.

## Usage

```bash
webscan vuln --defaultTemplateDirectory /opt/nuclei/templates --severity CRITICAL --target https://example.com
```

## Help Text

```bash
webscan vuln -h
Perform a vulnerability scan against a target using nuclei

Usage:
  webscan vuln [flags]

Flags:
      --customTemplateDirectory string    Directory to load custom templates from
      --defaultTemplateDirectory string   Directory to load default templates from
  -h, --help                              help for vuln
      --severity strings                  Severity to filter templates by
      --tags strings                      Tags to filter templates by
      --target string                     URL target to perform path fuzzing against

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
