const crypto = require('crypto');
const NodeRSA = require('node-rsa');
const fs = require('fs').promises;
const path = require('path');

class EncryptionService {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32; // 256 bits
    this.ivLength = 16;  // 128 bits
    this.tagLength = 16; // 128 bits
  }

  /**
   * Generate RSA key pair for a user
   * @returns {Object} - { publicKey, privateKey }
   */
  generateKeyPair() {
    const key = new NodeRSA({ b: 2048 });
    
    return {
      publicKey: key.exportKey('public'),
      privateKey: key.exportKey('private')
    };
  }

  /**
   * Generate a random AES key
   * @returns {Buffer} - 256-bit AES key
   */
  generateAESKey() {
    return crypto.randomBytes(this.keyLength);
  }

  /**
   * Encrypt data with AES-256-GCM
   * @param {Buffer} data - Data to encrypt
   * @param {Buffer} key - AES key
   * @returns {Object} - { encryptedData, iv, tag }
   */
  encryptAES(data, key) {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipherGCM(this.algorithm, key, iv);
    
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    const tag = cipher.getAuthTag();
    
    return {
      encryptedData: encrypted,
      iv: iv,
      tag: tag
    };
  }

  /**
   * Decrypt data with AES-256-GCM
   * @param {Buffer} encryptedData - Encrypted data
   * @param {Buffer} key - AES key
   * @param {Buffer} iv - Initialization vector
   * @param {Buffer} tag - Authentication tag
   * @returns {Buffer} - Decrypted data
   */
  decryptAES(encryptedData, key, iv, tag) {
    const decipher = crypto.createDecipherGCM(this.algorithm, key, iv);
    decipher.setAuthTag(tag);
    
    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted;
  }

  /**
   * Encrypt AES key with RSA public key
   * @param {Buffer} aesKey - AES key to encrypt
   * @param {string} publicKeyPem - RSA public key in PEM format
   * @returns {string} - Base64 encoded encrypted key
   */
  encryptKeyWithRSA(aesKey, publicKeyPem) {
    const key = new NodeRSA(publicKeyPem);
    const encrypted = key.encrypt(aesKey, 'base64');
    return encrypted;
  }

  /**
   * Decrypt AES key with RSA private key
   * @param {string} encryptedKey - Base64 encoded encrypted key
   * @param {string} privateKeyPem - RSA private key in PEM format
   * @returns {Buffer} - Decrypted AES key
   */
  decryptKeyWithRSA(encryptedKey, privateKeyPem) {
    const key = new NodeRSA(privateKeyPem);
    const decrypted = key.decrypt(encryptedKey);
    return decrypted;
  }

  /**
   * Encrypt a file and save it to disk
   * @param {string} inputPath - Path to input file
   * @param {string} outputPath - Path to save encrypted file
   * @param {string} publicKeyPem - RSA public key for key encryption
   * @returns {Object} - { encryptedKeyData, checksum }
   */
  async encryptFile(inputPath, outputPath, publicKeyPem) {
    try {
      // Read the file
      const fileData = await fs.readFile(inputPath);
      
      // Generate AES key for this file
      const aesKey = this.generateAESKey();
      
      // Encrypt the file data
      const { encryptedData, iv, tag } = this.encryptAES(fileData, aesKey);
      
      // Create the encrypted file structure
      const encryptedFileData = Buffer.concat([
        iv,                    // 16 bytes
        tag,                   // 16 bytes  
        encryptedData         // Variable length
      ]);
      
      // Save encrypted file
      await fs.writeFile(outputPath, encryptedFileData);
      
      // Encrypt the AES key with user's public key
      const encryptedKey = this.encryptKeyWithRSA(aesKey, publicKeyPem);
      
      // Generate checksum of original file
      const checksum = crypto.createHash('sha256').update(fileData).digest('hex');
      
      return {
        encryptedKeyData: encryptedKey,
        checksum: checksum
      };
      
    } catch (error) {
      throw new Error(`File encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt a file from disk
   * @param {string} encryptedPath - Path to encrypted file
   * @param {string} outputPath - Path to save decrypted file
   * @param {string} encryptedKey - Encrypted AES key (base64)
   * @param {string} privateKeyPem - RSA private key for key decryption
   * @returns {string} - Checksum of decrypted file
   */
  async decryptFile(encryptedPath, outputPath, encryptedKey, privateKeyPem) {
    try {
      // Read encrypted file
      const encryptedFileData = await fs.readFile(encryptedPath);
      
      // Extract components
      const iv = encryptedFileData.slice(0, this.ivLength);
      const tag = encryptedFileData.slice(this.ivLength, this.ivLength + this.tagLength);
      const encryptedData = encryptedFileData.slice(this.ivLength + this.tagLength);
      
      // Decrypt the AES key
      const aesKey = this.decryptKeyWithRSA(encryptedKey, privateKeyPem);
      
      // Decrypt the file data
      const decryptedData = this.decryptAES(encryptedData, aesKey, iv, tag);
      
      // Save decrypted file
      await fs.writeFile(outputPath, decryptedData);
      
      // Generate checksum for integrity verification
      const checksum = crypto.createHash('sha256').update(decryptedData).digest('hex');
      
      return checksum;
      
    } catch (error) {
      throw new Error(`File decryption failed: ${error.message}`);
    }
  }

  /**
   * Calculate file checksum
   * @param {string} filePath - Path to file
   * @returns {string} - SHA-256 checksum in hex
   */
  async calculateChecksum(filePath) {
    try {
      const fileData = await fs.readFile(filePath);
      return crypto.createHash('sha256').update(fileData).digest('hex');
    } catch (error) {
      throw new Error(`Checksum calculation failed: ${error.message}`);
    }
  }

  /**
   * Verify file integrity
   * @param {string} filePath - Path to file
   * @param {string} expectedChecksum - Expected checksum
   * @returns {boolean} - True if checksums match
   */
  async verifyIntegrity(filePath, expectedChecksum) {
    try {
      const actualChecksum = await this.calculateChecksum(filePath);
      return actualChecksum === expectedChecksum;
    } catch (error) {
      console.error('Integrity verification failed:', error);
      return false;
    }
  }

  /**
   * Generate secure random string for file names
   * @param {number} length - Length of random string
   * @returns {string} - Random hex string
   */
  generateSecureFilename(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Hash password with salt
   * @param {string} password - Plain text password
   * @param {number} saltRounds - Number of salt rounds (default: 12)
   * @returns {string} - Hashed password
   */
  async hashPassword(password, saltRounds = 12) {
    const bcrypt = require('bcryptjs');
    return await bcrypt.hash(password, saltRounds);
  }

  /**
   * Compare password with hash
   * @param {string} password - Plain text password
   * @param {string} hash - Hashed password
   * @returns {boolean} - True if password matches
   */
  async comparePassword(password, hash) {
    const bcrypt = require('bcryptjs');
    return await bcrypt.compare(password, hash);
  }

  /**
   * Generate verification code
   * @param {number} length - Length of code (default: 4)
   * @returns {string} - Numeric verification code
   */
  generateVerificationCode(length = 4) {
    const min = Math.pow(10, length - 1);
    const max = Math.pow(10, length) - 1;
    return Math.floor(Math.random() * (max - min + 1) + min).toString();
  }

  /**
   * Generate JWT token
   * @param {Object} payload - Token payload
   * @param {string} secret - JWT secret
   * @param {string} expiresIn - Token expiration
   * @returns {string} - JWT token
   */
  generateJWT(payload, secret, expiresIn = '1h') {
    const jwt = require('jsonwebtoken');
    return jwt.sign(payload, secret, { expiresIn });
  }

  /**
   * Encrypt sensitive data for database storage
   * @param {string} data - Data to encrypt
   * @param {string} key - Encryption key
   * @returns {string} - Encrypted data (base64)
   */
  encryptForStorage(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', crypto.scryptSync(key, 'salt', 32), iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return iv.toString('base64') + ':' + encrypted;
  }

  /**
   * Decrypt sensitive data from database storage
   * @param {string} encryptedData - Encrypted data (base64)
   * @param {string} key - Decryption key
   * @returns {string} - Decrypted data
   */
  decryptFromStorage(encryptedData, key) {
    const [ivBase64, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivBase64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', crypto.scryptSync(key, 'salt', 32), iv);
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }
}

module.exports = new EncryptionService();