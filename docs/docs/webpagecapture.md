# Spider

The `webscan webpagecapture` command collects the HTML from a specified URL target.

## Usage

```bash
webscan webpagecapture --targets https://example.com
```

## Help Text

```bash
webscan webpagecapture -h
Perform a webpage HTML capture against a URL target

Usage:
  webscan webpagecapture [flags]

Flags:
  -h, --help            help for webpagecapture
      --target string   Url target to perform webpage HTML capture

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
