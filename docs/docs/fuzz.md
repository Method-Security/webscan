# Fuzz

The `webscan fuzz` family of commands conduct basic fuzzing techniques to discover URLs and endpoints that may not be advertised.

## Path

### Usage

```bash
webscan fuzz path --maxtime 100 --pathlist paths.txt --target https://example.com
```

### Help Text

```bash
$ webscan fuzz path -h
Perform a path based web fuzz against a target

Usage:
  webscan fuzz path [flags]

Flags:
  -h, --help                   help for path
      --maxtime int            The maximum time in seconds to run the job, default to 300 seconds (default 300)
      --pathlist string        Newline separated list of paths to fuzz
      --responsecodes string   Response codes to consider as valid responses (default "200-299,401,403")
      --target string          URL target to perform path fuzzing against

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
