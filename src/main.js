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
    
    // Get home directory - handle both Windows and Unix
    const homeDir = process.env.HOME || process.env.USERPROFILE || process.env.HOMEPATH;
    if (!homeDir) {
      throw new Error('Cannot determine home directory. HOME, USERPROFILE, and HOMEPATH are all undefined.');
    }
    
    core.debug(`Home directory: ${homeDir}`);
    
    // Write kubeconfig to file
    const kubeconfigPath = path.join(homeDir, '.kube', 'config');
    const kubeconfigDir = path.dirname(kubeconfigPath);
    
    core.debug(`Kubeconfig path: ${kubeconfigPath}`);
    core.debug(`Kubeconfig directory: ${kubeconfigDir}`);
    
    if (!fs.existsSync(kubeconfigDir)) {
      core.debug('Creating .kube directory...');
      fs.mkdirSync(kubeconfigDir, { recursive: true });
    }
    
    // Validate kubeconfig content
    if (!this.kubeConfig || typeof this.kubeConfig !== 'string') {
      throw new Error('kubernetes-config input is empty or invalid');
    }
    
    if (this.kubeConfig.trim().length === 0) {
      throw new Error('kubernetes-config input is empty');
    }
    
    // Write the kubeconfig directly (no base64 decoding needed)
    core.debug('Writing kubeconfig file...');
    fs.writeFileSync(kubeconfigPath, this.kubeConfig);
    
    // Set file permissions (Unix-like systems)
    if (process.platform !== 'win32') {
      fs.chmodSync(kubeconfigPath, 0o600);
    }
    
    // Test kubectl connection
    try {
      core.debug('Testing kubectl connection...');
      execSync('kubectl version --client', { stdio: 'pipe' });
      core.info('✅ kubectl configured successfully');
    } catch (error) {
      core.error(`kubectl test failed: ${error.message}`);
      throw new Error(`Failed to configure kubectl: ${error.message}`);
    }
  }

  async extractSignatures() {
    core.info('📂 Extracting Tauri signatures...');
    
    // Validate bundle path
    if (!this.bundlePath || typeof this.bundlePath !== 'string') {
      throw new Error(`Invalid bundle path: ${this.bundlePath}`);
    }
    
    const absoluteBundlePath = path.resolve(this.bundlePath);
    core.info(`🔍 Bundle path: ${absoluteBundlePath}`);
    core.info(`📍 Current working directory: ${process.cwd()}`);
    
    if (!fs.existsSync(absoluteBundlePath)) {
      core.error(`❌ Bundle path does not exist: ${absoluteBundlePath}`);
      
      // Try to find Tauri directories for debugging
      try {
        const currentDir = process.cwd();
        core.info(`📂 Contents of current directory (${currentDir}):`);
        const files = fs.readdirSync(currentDir);
        files.slice(0, 10).forEach(file => {
          const fullPath = path.join(currentDir, file);
          const isDir = fs.statSync(fullPath).isDirectory();
          core.info(`  ${isDir ? '📁' : '📄'} ${file}`);
        });
        
        // Look for any tauri-related directories
        const findTauriDirs = (dir, maxDepth = 2) => {
          if (maxDepth <= 0) return [];
          try {
            const items = fs.readdirSync(dir);
            let tauriDirs = [];
            for (const item of items) {
              if (item.includes('tauri') || item.includes('target')) {
                const fullPath = path.join(dir, item);
                if (fs.statSync(fullPath).isDirectory()) {
                  tauriDirs.push(fullPath);
                  // Look one level deeper
                  tauriDirs = tauriDirs.concat(findTauriDirs(fullPath, maxDepth - 1));
                }
              }
            }
            return tauriDirs;
          } catch (e) {
            return [];
          }
        };
        
        const tauriDirs = findTauriDirs(currentDir);
        if (tauriDirs.length > 0) {
          core.info('🔍 Found Tauri-related directories:');
          tauriDirs.slice(0, 5).forEach(dir => core.info(`  📁 ${dir}`));
        }
        
      } catch (debugError) {
        core.warning(`Debug directory listing failed: ${debugError.message}`);
      }
      
      throw new Error(`Bundle directory not found: ${absoluteBundlePath}`);
    }
    
    // Update bundle path to absolute path
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
    
    core.info(`📊 Found ${this.signatureCount} signature files across ${Object.keys(this.signatures).length} platforms`);
    
    if (this.signatureCount === 0) {
      // Try to find .sig files anywhere in the bundle path
      core.info('🔍 Searching for .sig files recursively...');
      try {
        const findSigFiles = (dir, maxDepth = 3) => {
          if (maxDepth <= 0) return [];
          try {
            const items = fs.readdirSync(dir);
            let sigFiles = [];
            for (const item of items) {
              const fullPath = path.join(dir, item);
              const stat = fs.statSync(fullPath);
              if (stat.isFile() && item.endsWith('.sig')) {
                sigFiles.push(fullPath);
              } else if (stat.isDirectory()) {
                sigFiles = sigFiles.concat(findSigFiles(fullPath, maxDepth - 1));
              }
            }
            return sigFiles;
          } catch (e) {
            return [];
          }
        };
        
        const allSigFiles = findSigFiles(this.bundlePath);
        if (allSigFiles.length > 0) {
          core.info('📝 Found .sig files at:');
          allSigFiles.slice(0, 10).forEach(file => core.info(`  📄 ${file}`));
        } else {
          core.info('ℹ️ No .sig files found in bundle directory');
        }
      } catch (searchError) {
        core.warning(`Error searching for .sig files: ${searchError.message}`);
      }
    }
  }

  async extractPlatformSignatures(platform) {
    const signatures = {};
    
    for (const bundleType of PLATFORM_PATHS[platform]) {
      const bundleDir = path.join(this.bundlePath, bundleType);
      
      core.debug(`Checking bundle directory: ${bundleDir}`);
      
      if (!fs.existsSync(bundleDir)) {
        core.debug(`Bundle directory not found: ${bundleDir}`);
        continue;
      }
      
      try {
        const files = fs.readdirSync(bundleDir);
        core.debug(`Files in ${bundleDir}: ${files.join(', ')}`);
        
        const sigFiles = files.filter(file => file.endsWith('.sig'));
        core.debug(`Signature files found: ${sigFiles.join(', ')}`);
        
        for (const sigFile of sigFiles) {
          const sigPath = path.join(bundleDir, sigFile);
          
          // Validate file path
          if (!sigPath || typeof sigPath !== 'string') {
            core.warning(`Invalid signature file path: ${sigPath}`);
            continue;
          }
          
          if (!fs.existsSync(sigPath)) {
            core.warning(`Signature file does not exist: ${sigPath}`);
            continue;
          }
          
          try {
            const sigContent = fs.readFileSync(sigPath, 'utf8').trim();
            
            if (!sigContent) {
              core.warning(`Empty signature file: ${sigPath}`);
              continue;
            }
            
            // Generate a hash of the signature for verification
            const sigHash = crypto.createHash('sha256').update(sigContent).digest('hex');
            
            // Sanitize filename for use as key
            const filename = path.basename(sigFile, '.sig').replace(/[^a-zA-Z0-9._-]/g, '_');
            
            if (!filename) {
              core.warning(`Invalid filename after sanitization: ${sigFile}`);
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
            core.info(`✅ Extracted signature: ${platform}/${key}`);
            
          } catch (fileError) {
            core.warning(`Error reading signature file ${sigPath}: ${fileError.message}`);
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
    const metadata = {
      platforms: Object.keys(this.signatures),
      totalSignatures: this.signatureCount,
      extractedAt: new Date().toISOString(),
      githubRef: process.env.GITHUB_REF || 'unknown',
      githubSha: process.env.GITHUB_SHA || 'unknown',
      bundlePath: this.bundlePath
    };
    
    data[`${this.keyPrefix}-metadata`] = Buffer.from(JSON.stringify(metadata)).toString('base64');
    
    // Add signature data
    for (const [platform, platformSigs] of Object.entries(this.signatures)) {
      for (const [key, sigData] of Object.entries(platformSigs)) {
        const secretKey = `${this.keyPrefix}-${platform}-${key}`;
        
        // Validate the key doesn't contain invalid characters
        const validKey = secretKey.replace(/[^a-zA-Z0-9._-]/g, '-');
        if (validKey !== secretKey) {
          core.warning(`Secret key sanitized: ${secretKey} -> ${validKey}`);
        }
        
        try {
          data[validKey] = Buffer.from(JSON.stringify(sigData)).toString('base64');
        } catch (encodeError) {
          core.error(`Failed to encode signature data for key ${validKey}: ${encodeError.message}`);
        }
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