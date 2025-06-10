const core = require('@actions/core');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

// Platform-specific bundle paths
const PLATFORM_PATHS = {
  windows: ['msi', 'nsis'],
  macos: ['macos', 'dmg'],
  linux: ['deb', 'rpm', 'appimage']
};

class TauriSignatureExtractor {
  constructor() {
    this.bundlePath = core.getInput('tauri-bundle-path');
    this.kubeConfig = core.getInput('kubernetes-config');
    this.namespace = core.getInput('kubernetes-namespace');
    this.secretName = core.getInput('secret-name');
    this.keyPrefix = core.getInput('secret-key-prefix');
    this.platforms = core.getInput('platforms').split(',').map(p => p.trim());
    this.githubToken = core.getInput('github-token');
    
    this.signatures = {};
    this.signatureCount = 0;
  }

  async run() {
    try {
      core.info('🔍 Starting Tauri signature extraction...');
      
      // Setup kubectl
      await this.setupKubectl();
      
      // Find and extract signatures
      await this.extractSignatures();
      
      // Update Kubernetes secret
      await this.updateKubernetesSecret();
      
      // Set outputs
      core.setOutput('signatures-found', this.signatureCount);
      core.setOutput('secret-updated', 'true');
      core.setOutput('signature-hashes', JSON.stringify(this.signatures));
      
      core.info('✅ Tauri signatures successfully stored in Kubernetes secret!');
      
    } catch (error) {
      core.setFailed(`Action failed: ${error.message}`);
    }
  }

  async setupKubectl() {
    core.info('🔧 Setting up kubectl...');
    
    // Write kubeconfig to file
    const kubeconfigPath = path.join(process.env.HOME, '.kube', 'config');
    const kubeconfigDir = path.dirname(kubeconfigPath);
    
    if (!fs.existsSync(kubeconfigDir)) {
      fs.mkdirSync(kubeconfigDir, { recursive: true });
    }
    
    // Write the kubeconfig directly (no base64 decoding needed)
    fs.writeFileSync(kubeconfigPath, this.kubeConfig);
    
    // Test kubectl connection
    try {
      execSync('kubectl version --client', { stdio: 'pipe' });
      core.info('✅ kubectl configured successfully');
    } catch (error) {
      throw new Error(`Failed to configure kubectl: ${error.message}`);
    }
  }

  async extractSignatures() {
    core.info('📂 Extracting Tauri signatures...');
    
    for (const platform of this.platforms) {
      if (!PLATFORM_PATHS[platform]) {
        core.warning(`⚠️ Unknown platform: ${platform}`);
        continue;
      }
      
      const platformSignatures = await this.extractPlatformSignatures(platform);
      if (Object.keys(platformSignatures).length > 0) {
        this.signatures[platform] = platformSignatures;
      }
    }
    
    core.info(`📊 Found ${this.signatureCount} signature files across ${Object.keys(this.signatures).length} platforms`);
  }

  async extractPlatformSignatures(platform) {
    const signatures = {};
    
    for (const bundleType of PLATFORM_PATHS[platform]) {
      const bundleDir = path.join(this.bundlePath, bundleType);
      
      if (!fs.existsSync(bundleDir)) {
        core.debug(`📁 Bundle directory not found: ${bundleDir}`);
        continue;
      }
      
      try {
        const files = fs.readdirSync(bundleDir);
        const sigFiles = files.filter(file => file.endsWith('.sig'));
        
        for (const sigFile of sigFiles) {
          const sigPath = path.join(bundleDir, sigFile);
          const sigContent = fs.readFileSync(sigPath, 'utf8').trim();
          
          // Generate a hash of the signature for verification
          const sigHash = crypto.createHash('sha256').update(sigContent).digest('hex');
          
          const key = `${bundleType}-${path.basename(sigFile, '.sig')}`;
          signatures[key] = {
            content: sigContent,
            hash: sigHash,
            file: sigFile,
            timestamp: new Date().toISOString()
          };
          
          this.signatureCount++;
          core.info(`✅ Extracted signature: ${platform}/${key}`);
        }
      } catch (error) {
        core.warning(`⚠️ Error processing ${platform}/${bundleType}: ${error.message}`);
      }
    }
    
    return signatures;
  }

  async updateKubernetesSecret() {
    core.info('🔐 Updating Kubernetes secret...');
    
    try {
      // Check if secret exists
      const secretExists = await this.checkSecretExists();
      
      // Prepare secret data
      const secretData = this.prepareSecretData();
      
      if (secretExists) {
        await this.patchSecret(secretData);
      } else {
        await this.createSecret(secretData);
      }
      
      core.info('✅ Kubernetes secret updated successfully');
      
    } catch (error) {
      throw new Error(`Failed to update Kubernetes secret: ${error.message}`);
    }
  }

  async checkSecretExists() {
    try {
      execSync(`kubectl get secret ${this.secretName} -n ${this.namespace}`, { stdio: 'pipe' });
      return true;
    } catch (error) {
      return false;
    }
  }

  prepareSecretData() {
    const data = {};
    
    // Add metadata
    data[`${this.keyPrefix}-metadata`] = Buffer.from(JSON.stringify({
      platforms: Object.keys(this.signatures),
      totalSignatures: this.signatureCount,
      extractedAt: new Date().toISOString(),
      githubRef: process.env.GITHUB_REF,
      githubSha: process.env.GITHUB_SHA
    })).toString('base64');
    
    // Add signature data
    for (const [platform, platformSigs] of Object.entries(this.signatures)) {
      for (const [key, sigData] of Object.entries(platformSigs)) {
        const secretKey = `${this.keyPrefix}-${platform}-${key}`;
        data[secretKey] = Buffer.from(JSON.stringify(sigData)).toString('base64');
      }
    }
    
    return data;
  }

  async createSecret(secretData) {
    const secretManifest = {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: this.secretName,
        namespace: this.namespace,
        labels: {
          'app.kubernetes.io/name': 'tauri-signatures',
          'app.kubernetes.io/created-by': 'github-action'
        }
      },
      type: 'Opaque',
      data: secretData
    };
    
    const manifestPath = '/tmp/secret-manifest.yaml';
    fs.writeFileSync(manifestPath, JSON.stringify(secretManifest));
    
    execSync(`kubectl apply -f ${manifestPath}`, { stdio: 'pipe' });
    core.info('📝 Created new Kubernetes secret');
  }

  async patchSecret(secretData) {
    // Create patch data
    const patchData = { data: secretData };
    const patchPath = '/tmp/secret-patch.json';
    fs.writeFileSync(patchPath, JSON.stringify(patchData));
    
    execSync(`kubectl patch secret ${this.secretName} -n ${this.namespace} --patch-file ${patchPath}`, { stdio: 'pipe' });
    core.info('🔄 Patched existing Kubernetes secret');
  }
}

// Run the action
if (require.main === module) {
  const extractor = new TauriSignatureExtractor();
  extractor.run();
}

module.exports = TauriSignatureExtractor;