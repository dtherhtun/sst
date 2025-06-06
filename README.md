# SST — Sealed Secrets Tool

A utility for working with Kubernetes Sealed Secrets across clusters and namespaces.

## Description

SST makes it easy to:
- Copy secrets between namespaces or clusters
- Export sealed secrets as YAML files (especially for GitOps)
- Create sealed secrets directly in another namespace/cluster
- Inject additional key=value data into existing sealed secrets

## Installation

```bash
go install github.com/dtherhtun/sst/cmd/sst@latest
```

Or clone and build:

```bash
git clone https://github.com/dtherhtun/sst.git
cd sst
go build -o sst ./cmd/sst
```

## Usage

```bash
# Export all secrets from the current namespace to YAML files
sst

# Export secrets from a specific namespace to YAML files
sst -src-ns=source-ns

# Export a specific secret and inject additional values
sst -src-ns=source-ns -secret-name=my-secret -from-literal=key=value

# Export secrets from one cluster context to another
sst -src-ctx=source-ctx -dst-ctx=dest-ctx -src-ns=source-ns -dst-ns=dest-ns

# Directly create sealed secrets in the destination namespace
sst --export-mode=direct -src-ns=source-ns -dst-ns=dest-ns
```

## Options

```
  -kubeconfig string         Path to kubeconfig file (default "~/.kube/config")
  -src-ctx string            Source cluster context
  -dst-ctx string            Destination cluster context
  -src-ns string             Source namespace
  -dst-ns string             Destination namespace
  -export-mode string        Export mode: 'yaml' or 'direct' (default "yaml")
  -output-dir string         Output directory for YAML files (default "sealed-secrets")
  -sealed-secret-ns string   Sealed secrets namespace (default "kube-system")
  -secret-name string        Specific secret name to process (optional)
  -from-literal key=value    Key-value pairs to inject into secret (can be used multiple times)
  -from-file string          Files containing key-value pairs to inject into secret (can be used multiple times)
```
