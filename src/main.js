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
    this.namespace = core.getInput('kubernetes-namespace') || 'default';
    this.secretName = core.getInput('secret-name');
    this.keyPrefix = core.getInput('secret-key-prefix') || 'tauri-sig';
    this.platforms = (core.getInput('platforms') || 'windows,macos,linux').split(',').map(p => p.trim());
    
    this.signatures = {};
    this.signatureCount = 0;
  }

  async run() {
    try {
      core.info('🔍 Starting Tauri signature extraction...');
      const os = require('os');
      core.info(`🖥️ Platform: ${os.platform()}`);
      core.info(`📍 Current directory: ${process.cwd()}`);
      
      // Validate inputs
      if (!this.bundlePath) {
        throw new Error('tauri-bundle-path input is required');
      }
      
      if (!this.kubeConfig) {
        throw new Error('kubernetes-config input is required');
      }
      
      if (!this.secretName) {
        throw new Error('secret-name input is required');
      }
      
      core.info(`🎯 Target secret: ${this.secretName} in namespace: ${this.namespace}`);
      core.info(`🏷️ Key prefix: ${this.keyPrefix}`);
      core.info(`🖥️ Platforms: ${this.platforms.join(', ')}`);
      
      // Setup kubectl
      await this.setupKubectl();
      
      // Find and extract signatures
      await this.extractSignatures();
      
      if (this.signatureCount === 0) {
        core.warning('⚠️ No signature files found. Skipping Kubernetes secret update.');
        core.setOutput('signatures-found', '0');
        core.setOutput('secret-updated', 'false');
        core.setOutput('signature-hashes', '{}');
        return;
      }
      
      // Update only the signature key in the secret
      await this.updateSignatureInSecret();
      
      // Set outputs
      core.setOutput('signatures-found', this.signatureCount.toString());
      core.setOutput('secret-updated', 'true');
      core.setOutput('signature-hashes', JSON.stringify(this.signatures));
      
      core.info('✅ Tauri signature successfully updated in Kubernetes secret!');
      
    } catch (error) {
      core.error(`❌ Action failed: ${error.message}`);
      if (error.stack) {
        core.debug(`Stack trace: ${error.stack}`);
      }
      core.setFailed(`Action failed: ${error.message}`);
    }
  }

  async setupKubectl() {
    core.info('🔧 Setting up kubectl...');
    
    // Use os.homedir() which is more reliable across platforms
    let homeDir;
    try {
      const os = require('os');
      homeDir = os.homedir();
      core.info(`🏠 Home directory: ${homeDir}`);
    } catch (e) {
      // Fallback for edge cases
      homeDir = process.env.HOME || process.env.USERPROFILE || process.env.HOMEPATH || '/tmp';
      core.warning(`Using fallback home directory: ${homeDir}`);
    }
    
    if (!homeDir || typeof homeDir !== 'string') {
      throw new Error('Cannot determine home directory');
    }
    
    // Write kubeconfig to file
    const kubeconfigPath = path.join(homeDir, '.kube', 'config');
    const kubeconfigDir = path.dirname(kubeconfigPath);
    
    core.info(`📝 Kubeconfig path: ${kubeconfigPath}`);
    
    if (!fs.existsSync(kubeconfigDir)) {
      core.info('📁 Creating .kube directory...');
      fs.mkdirSync(kubeconfigDir, { recursive: true });
    }
    
    // Validate kubeconfig content
    if (!this.kubeConfig || typeof this.kubeConfig !== 'string') {
      throw new Error('kubernetes-config input is empty or invalid');
    }
    
    if (this.kubeConfig.trim().length === 0) {
      throw new Error('kubernetes-config input is empty');
    }
    
    // Write the kubeconfig
    fs.writeFileSync(kubeconfigPath, this.kubeConfig);
    
    // Set file permissions (Unix-like systems only)
    if (process.platform !== 'win32') {
      try {
        fs.chmodSync(kubeconfigPath, 0o600);
      } catch (e) {
        core.warning(`Could not set kubeconfig permissions: ${e.message}`);
      }
    }
    
    // Test kubectl is available (don't check version to avoid compatibility issues)
    try {
      execSync('kubectl --help', { stdio: 'pipe' });
      core.info(`✅ kubectl configured successfully`);
    } catch (error) {
      core.error(`kubectl setup failed: ${error.message}`);
      throw new Error(`Failed to configure kubectl: ${error.message}`);
    }
  }

  async extractSignatures() {
    core.info('📂 Extracting Tauri signatures...');
    
    // Validate and resolve bundle path
    if (!this.bundlePath || typeof this.bundlePath !== 'string') {
      throw new Error(`Invalid bundle path: ${this.bundlePath}`);
    }
    
    const absoluteBundlePath = path.resolve(this.bundlePath);
    core.info(`🔍 Bundle path: ${absoluteBundlePath}`);
    
    if (!fs.existsSync(absoluteBundlePath)) {
      core.error(`❌ Bundle path does not exist: ${absoluteBundlePath}`);
      throw new Error(`Bundle directory not found: ${absoluteBundlePath}`);
    }
    
    this.bundlePath = absoluteBundlePath;
    
    for (const platform of this.platforms) {
      if (!PLATFORM_PATHS[platform]) {
        core.warning(`⚠️ Unknown platform: ${platform}`);
        continue;
      }
      
      core.info(`🔍 Processing platform: ${platform}`);
      const platformSignatures = await this.extractPlatformSignatures(platform);
      if (Object.keys(platformSignatures).length > 0) {
        this.signatures[platform] = platformSignatures;
        core.info(`✅ Found ${Object.keys(platformSignatures).length} signatures for ${platform}`);
      } else {
        core.info(`ℹ️ No signatures found for ${platform}`);
      }
    }
    
    core.info(`📊 Total: ${this.signatureCount} signature files across ${Object.keys(this.signatures).length} platforms`);
  }

  async extractPlatformSignatures(platform) {
    const signatures = {};
    
    for (const bundleType of PLATFORM_PATHS[platform]) {
      const bundleDir = path.join(this.bundlePath, bundleType);
      
      core.info(`📁 Checking: ${bundleDir}`);
      
      if (!fs.existsSync(bundleDir)) {
        core.info(`📁 Not found: ${bundleDir}`);
        continue;
      }
      
      try {
        const files = fs.readdirSync(bundleDir);
        core.info(`📄 Files in ${bundleType}: ${files.join(', ')}`);
        
        const sigFiles = files.filter(file => file.endsWith('.sig'));
        core.info(`🔐 Signature files: ${sigFiles.join(', ')}`);
        
        for (const sigFile of sigFiles) {
          const sigPath = path.join(bundleDir, sigFile);
          
          if (!fs.existsSync(sigPath)) {
            core.warning(`⚠️ Signature file missing: ${sigPath}`);
            continue;
          }
          
          try {
            const sigContent = fs.readFileSync(sigPath, 'utf8').trim();
            
            if (!sigContent) {
              core.warning(`⚠️ Empty signature file: ${sigPath}`);
              continue;
            }
            
            const sigHash = crypto.createHash('sha256').update(sigContent).digest('hex');
            const filename = path.basename(sigFile, '.sig').replace(/[^a-zA-Z0-9._-]/g, '_');
            
            if (!filename) {
              core.warning(`⚠️ Invalid filename: ${sigFile}`);
              continue;
            }
            
            const key = `${bundleType}-${filename}`;
            signatures[key] = {
              content: sigContent,
              hash: sigHash,
              file: sigFile,
              timestamp: new Date().toISOString(),
              path: sigPath
            };
            
            this.signatureCount++;
            core.info(`✅ Extracted: ${platform}/${key}`);
            
          } catch (fileError) {
            core.warning(`⚠️ Error reading ${sigPath}: ${fileError.message}`);
          }
        }
      } catch (error) {
        core.warning(`⚠️ Error processing ${platform}/${bundleType}: ${error.message}`);
      }
    }
    
    return signatures;
  }

  async updateSignatureInSecret() {
    core.info('🔐 Updating signature in Kubernetes secret...');
    
    // Check if secret exists
    const secretExists = await this.checkSecretExists();
    if (!secretExists) {
      throw new Error(`Secret ${this.secretName} does not exist. Please create it first with your application environment variables.`);
    }
    
    // Find the main signature
    const mainSignature = this.findMainSignature();
    if (!mainSignature) {
      throw new Error('No suitable signature found to update');
    }
    
    core.info(`📝 Updating ${this.keyPrefix} with signature from ${mainSignature.file}`);
    
    // Create patch data with just the signature key
    const signatureValue = Buffer.from(mainSignature.content).toString('base64');
    const patchData = {
      data: {
        [this.keyPrefix]: signatureValue
      }
    };
    
    try {
      // Use kubectl patch with merge strategy via stdin
      const patchJson = JSON.stringify(patchData, null, 2);
      core.info(`📄 Patch content: ${patchJson}`);
      
      execSync(`kubectl patch secret "${this.secretName}" -n "${this.namespace}" --type merge --patch-file -`, {
        input: patchJson,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      core.info(`✅ Successfully updated ${this.keyPrefix} in secret ${this.secretName}`);
      
    } catch (error) {
      throw new Error(`Failed to patch secret: ${error.message}`);
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

  findMainSignature() {
    // Find the main signature file based on platform and file patterns
    for (const [platform, platformSigs] of Object.entries(this.signatures)) {
      for (const [key, sigData] of Object.entries(platformSigs)) {
        if (platform === 'windows') {
          // For Windows, prefer MSI signature that's not a zip
          if (sigData.file && sigData.file.includes('.msi.sig') && !sigData.file.includes('.zip.sig')) {
            return sigData;
          }
        } else if (platform === 'macos') {
          // For macOS, prefer DMG signature or the first available
          if (sigData.file && (sigData.file.includes('.dmg.sig') || sigData.file.includes('.app.tar.gz.sig'))) {
            return sigData;
          }
        } else if (platform === 'linux') {
          // For Linux, prefer DEB signature or the first available
          if (sigData.file && sigData.file.includes('.deb.sig')) {
            return sigData;
          }
        }
      }
    }
    
    // Fallback: return the first signature found
    for (const [platform, platformSigs] of Object.entries(this.signatures)) {
      const firstSig = Object.values(platformSigs)[0];
      if (firstSig) {
        core.info(`📝 Using fallback signature: ${firstSig.file}`);
        return firstSig;
      }
    }
    
    return null;
  }
}

// Run the action
if (require.main === module) {
  const extractor = new TauriSignatureExtractor();
  extractor.run();
}

module.exports = TauriSignatureExtractor;