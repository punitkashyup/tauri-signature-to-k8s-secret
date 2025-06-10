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
        core.warning('⚠️ No signature files found. Skipping Kubernetes secret creation.');
        core.setOutput('signatures-found', '0');
        core.setOutput('secret-updated', 'false');
        core.setOutput('signature-hashes', '{}');
        return;
      }
      
      // Update Kubernetes secret
      await this.updateKubernetesSecret();
      
      // Set outputs
      core.setOutput('signatures-found', this.signatureCount.toString());
      core.setOutput('secret-updated', 'true');
      core.setOutput('signature-hashes', JSON.stringify(this.signatures));
      
      core.info('✅ Tauri signatures successfully stored in Kubernetes secret!');
      
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
    
    // Test kubectl connection
    try {
      execSync('kubectl version --client', { stdio: 'pipe' });
      core.info('✅ kubectl configured successfully');
    } catch (error) {
      core.error(`kubectl test failed: ${error.message}`);
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
      
      // Debug information
      try {
        const currentDir = process.cwd();
        core.info(`📂 Contents of current directory (${currentDir}):`);
        const files = fs.readdirSync(currentDir);
        files.slice(0, 10).forEach(file => {
          const fullPath = path.join(currentDir, file);
          const isDir = fs.lstatSync(fullPath).isDirectory();
          core.info(`  ${isDir ? '📁' : '📄'} ${file}`);
        });
        
        // Look for tauri directories
        const tauriDirs = files.filter(file => 
          file.includes('tauri') || file.includes('target') || file.includes('apps')
        );
        if (tauriDirs.length > 0) {
          core.info('🔍 Found potential Tauri directories:');
          tauriDirs.forEach(dir => core.info(`  📁 ${dir}`));
        }
      } catch (debugError) {
        core.warning(`Debug listing failed: ${debugError.message}`);
      }
      
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
    
    if (this.signatureCount === 0) {
      core.info('🔍 Searching for .sig files recursively...');
      this.findAllSigFiles(this.bundlePath);
    }
  }

  findAllSigFiles(dir, maxDepth = 3) {
    if (maxDepth <= 0) return;
    
    try {
      const items = fs.readdirSync(dir);
      for (const item of items) {
        const fullPath = path.join(dir, item);
        const stat = fs.lstatSync(fullPath);
        
        if (stat.isFile() && item.endsWith('.sig')) {
          core.info(`📝 Found .sig file: ${fullPath}`);
        } else if (stat.isDirectory()) {
          this.findAllSigFiles(fullPath, maxDepth - 1);
        }
      }
    } catch (e) {
      core.debug(`Cannot read directory ${dir}: ${e.message}`);
    }
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

  async updateKubernetesSecret() {
    core.info('🔐 Updating Kubernetes secret...');
    
    try {
      const secretExists = await this.checkSecretExists();
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
    
    const metadata = {
      platforms: Object.keys(this.signatures),
      totalSignatures: this.signatureCount,
      extractedAt: new Date().toISOString(),
      githubRef: process.env.GITHUB_REF || 'unknown',
      githubSha: process.env.GITHUB_SHA || 'unknown',
      bundlePath: this.bundlePath
    };
    
    data[`${this.keyPrefix}-metadata`] = Buffer.from(JSON.stringify(metadata)).toString('base64');
    
    for (const [platform, platformSigs] of Object.entries(this.signatures)) {
      for (const [key, sigData] of Object.entries(platformSigs)) {
        const secretKey = `${this.keyPrefix}-${platform}-${key}`.replace(/[^a-zA-Z0-9._-]/g, '-');
        
        try {
          data[secretKey] = Buffer.from(JSON.stringify(sigData)).toString('base64');
        } catch (encodeError) {
          core.error(`Failed to encode signature data for key ${secretKey}: ${encodeError.message}`);
        }
      }
    }
    
    return data;
  }

  async createSecret(secretData) {
    core.info('📝 Creating new Kubernetes secret');
    
    // Use kubectl create secret with --from-literal for each key
    const args = [
      'create', 'secret', 'generic', this.secretName,
      '-n', this.namespace
    ];
    
    // Add each signature as a literal
    for (const [key, value] of Object.entries(secretData)) {
      args.push('--from-literal');
      args.push(`${key}=${value}`);
    }
    
    try {
      execSync(`kubectl ${args.join(' ')}`, { stdio: 'pipe' });
      core.info('✅ Created new Kubernetes secret');
    } catch (e) {
      throw new Error(`Failed to create secret: ${e.message}`);
    }
  }

  async patchSecret(secretData) {
    core.info('🔄 Patching existing Kubernetes secret');
    
    // Delete and recreate (simpler than complex patching)
    try {
      execSync(`kubectl delete secret "${this.secretName}" -n "${this.namespace}"`, { stdio: 'pipe' });
      core.info('🗑️ Deleted existing secret');
    } catch (e) {
      core.warning(`Could not delete existing secret: ${e.message}`);
    }
    
    // Create new secret
    await this.createSecret(secretData);
  }
}

// Run the action
if (require.main === module) {
  const extractor = new TauriSignatureExtractor();
  extractor.run();
}

module.exports = TauriSignatureExtractor;