# Tauri Signature to Kubernetes Secret

A GitHub Action that extracts Tauri build signatures and stores them securely in Kubernetes secrets.

## 🚀 Features

- **Multi-platform Support**: Extracts signatures from Windows (MSI/NSIS), macOS (DMG/macOS), and Linux (DEB/RPM/AppImage) builds
- **Kubernetes Integration**: Automatically creates or updates Kubernetes secrets
- **Secure Storage**: Base64 encoded signature data with metadata
- **Flexible Configuration**: Customizable secret names, namespaces, and key prefixes
- **Build Verification**: Generates SHA256 hashes for signature verification

## 📋 Prerequisites

- Tauri application with updater configured
- Kubernetes cluster access
- Base64 encoded kubeconfig in GitHub secrets

## 🔧 Usage

```yaml
- name: Extract and Store Tauri Signatures
  uses: yourusername/tauri-signature-to-k8s-secret@v1
  with:
    tauri-bundle-path: 'src-tauri/target/release/bundle'
    kubernetes-config: ${{ secrets.KUBE_CONFIG_BASE64 }}
    kubernetes-namespace: 'default'
    secret-name: 'tauri-signatures'
    secret-key-prefix: 'app-sig'
    platforms: 'windows,macos,linux'
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## 📝 Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `tauri-bundle-path` | Path to Tauri bundle directory | ✅ | `src-tauri/target/release/bundle` |
| `kubernetes-config` | Base64 encoded kubeconfig content | ✅ | - |
| `kubernetes-namespace` | Kubernetes namespace for the secret | ❌ | `default` |
| `secret-name` | Name of the Kubernetes secret | ✅ | - |
| `secret-key-prefix` | Prefix for secret keys | ❌ | `tauri-sig` |
| `platforms` | Comma-separated platforms to process | ❌ | `windows,macos,linux` |
| `github-token` | GitHub token for authentication | ❌ | `${{ github.token }}` |

## 📤 Outputs

| Output | Description |
|--------|-------------|
| `signatures-found` | Number of signature files found |
| `secret-updated` | Whether the Kubernetes secret was updated |
| `signature-hashes` | JSON object containing signature hashes by platform |

## 🗂️ Secret Structure

The action creates a Kubernetes secret with the following structure:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: tauri-signatures
  namespace: default
  labels:
    app.kubernetes.io/name: tauri-signatures
    app.kubernetes.io/created-by: github-action
type: Opaque
data:
  # Metadata about the extraction
  tauri-sig-metadata: <base64-encoded-json>
  
  # Platform-specific signatures
  tauri-sig-windows-msi-app: <base64-encoded-signature-data>
  tauri-sig-macos-dmg-app: <base64-encoded-signature-data>
  # ... more signatures
```

Each signature entry contains:
```json
{
  "content": "signature-content-from-sig-file",
  "hash": "sha256-hash-of-signature",
  "file": "original-filename.sig",
  "timestamp": "2025-06-10T12:00:00.000Z"
}
```

## 🔐 Required Secrets

Add these secrets to your GitHub repository:

- `KUBE_CONFIG_BASE64`: Base64 encoded kubeconfig file
- `GITHUB_TOKEN`: GitHub token (usually automatic)

## 🛠️ Complete Workflow Example

```yaml
name: Build and Store Signatures

on:
  push:
    branches: [main, development]

jobs:
  build-and-sign:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [windows-latest, macos-latest, ubuntu-latest]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      
      - name: Build Tauri App
        run: |
          npm install
          npm run tauri build
        env:
          TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_PRIVATE_KEY }}
          TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_KEY_PASSWORD }}
      
      - name: Extract and Store Signatures
        uses: yourusername/tauri-signature-to-k8s-secret@v1
        with:
          tauri-bundle-path: 'src-tauri/target/release/bundle'
          kubernetes-config: ${{ secrets.KUBE_CONFIG_BASE64 }}
          kubernetes-namespace: 'production'
          secret-name: 'app-signatures'
          platforms: ${{ matrix.os == 'windows-latest' && 'windows' || matrix.os == 'macos-latest' && 'macos' || 'linux' }}
```

## 🔍 Accessing Signatures in Kubernetes

Once stored, you can access the signatures in your Kubernetes applications:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: updater-service
spec:
  template:
    spec:
      containers:
      - name: updater
        image: updater:latest
        env:
        - name: WINDOWS_SIG
          valueFrom:
            secretKeyRef:
              name: tauri-signatures
              key: tauri-sig-windows-msi-app
        - name: MACOS_SIG
          valueFrom:
            secretKeyRef:
              name: tauri-signatures
              key: tauri-sig-macos-dmg-app
```

## 🐛 Troubleshooting

### Common Issues

1. **kubectl not found**: Ensure the runner has kubectl installed
2. **Permission denied**: Check kubeconfig permissions and RBAC settings
3. **No signatures found**: Verify the bundle path and ensure Tauri signing is enabled
4. **Secret update failed**: Check namespace exists and kubectl has write permissions

### Debug Mode

Enable debug logging by setting:
```yaml
env:
  ACTIONS_STEP_DEBUG: true
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📚 Related

- [Tauri Documentation](https://tauri.app/)
- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [GitHub Actions](https://docs.github.com/en/actions)