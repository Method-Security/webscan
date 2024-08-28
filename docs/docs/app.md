# App

The `webscan app` command performs various application scans such as fingerprinting and enumeration.

## Usage

```bash
webscan app [command]
```
## Commands

### Fingerprint

The `webscan app fingerprint` command fingerprints a URL by identifying the web application type.

Fingerprint uses [Nuclei](https://github.com/projectdiscovery/nuclei) as the means for identifying an application type.
For example, `--tags swagger` finds an active Swagger API. `--tags bucket` finds AWS S3 buckets of Azure Blob Storage Containers.

#### Usage

```bash
webscan app fingerprint --target https://example.com --tags swagger --severity INFO --defaultTemplateDirectory /path/to/default/templates --customTemplateDirectory /path/to/custom/templates
```

#### Help Text

```bash
webscan app fingerprint -h

Perform a fingerprint scan against a target

Usage:
webscan app fingerprint [flags]

Flags:
-h, --help help for fingerprint
--target string URL target to perform fingerprinting against
--tags strings Tags to filter templates by (default [swagger,k8s,graphql,grpc])
--severity strings Severity to filter templates by
--defaultTemplateDirectory Directory to load default templates from
--customTemplateDirectory Directory to load custom templates from

Global Flags:
-o, --output string Output format (signal, json, yaml). Default value is signal (default "signal")
-f, --output-file string Path to output file. If blank, will output to STDOUT
-q, --quiet Suppress output
-v, --verbose Verbose output

```

### Enumerate

The `webscan app enumerate` command details the routes for an API application.

#### Usage
```bash
webscan app enumerate [command]
```

#### Commands

##### Swagger

The `webscan app enumerate swagger` command performs a Swagger enumeration scan against a target.

###### Usage

```bash 
webscan app enumerate swagger --target https://example.com --no-sandbox
```

###### Help Text
```bash
webscan app enumerate swagger -h
Perform a Swagger enumeration scan against a target
Usage:
webscan app enumerate swagger [flags]
Flags:
-h, --help help for swagger
--target string URL target to perform Swagger enumeration against
--no-sandbox Disable sandbox mode for Swagger scan. Boolean flag, default false. 
Global Flags:
-o, --output string Output format (signal, json, yaml). Default value is signal (default "signal")
-f, --output-file string Path to output file. If blank, will output to STDOUT
-q, --quiet Suppress output
-v, --verbose Verbose output
```

##### gRPC

The `webscan app enumerate grpc` command performs a gRPC enumeration scan against a target.

###### Usage

```bash
webscan app enumerate grpc --target grpc.example.com:443
```

###### Help Text
```bash
webscan app enumerate grpc -h
Perform a gRPC enumeration scan against a target
Usage:
webscan app enumerate grpc [flags]
Flags:
-h, --help help for grpc
--target string URL target to perform gRPC enumeration against
Global Flags:
-o, --output string Output format (signal, json, yaml). Default value is signal (default "signal")
-f, --output-file string Path to output file. If blank, will output to STDOUT
-q, --quiet Suppress output
-v, --verbose Verbose output
```

##### GraphQL

The `webscan app enumerate graphql` command performs a GraphQL enumeration scan against a target.

###### Usage

```bash
webscan app enumerate graphql --target https://example.com
```

###### Help Text
```bash 
webscan app enumerate graphql -h
Perform a GraphQL enumeration scan against a target
Usage:
webscan app enumerate graphql [flags]
Flags:
-h, --help help for graphql
--target string URL target to perform GraphQL enumeration against
Global Flags:
-o, --output string Output format (signal, json, yaml). Default value is signal (default "signal")
-f, --output-file string Path to output file. If blank, will output to STDOUT
-q, --quiet Suppress output
-v, --verbose Verbose output
```