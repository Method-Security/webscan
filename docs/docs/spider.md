# Spider

The `webscan spider` command [crawls](https://en.wikipedia.org/wiki/Web_crawler) the provided targets, capturing data about URLs hosted and the provided addresses.

## Usage

```bash
webscan spider --targets https://example.com
```

## Help Text

```bash
webscan spider -h
Perform a web spider crawl against URL targets

Usage:
  webscan spider [flags]

Flags:
  -h, --help             help for spider
      --targets string   Url targets to perform web spidering, comma delimited list

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
