require('dotenv').config();
const readline = require('readline');
const database = require('../database/connection');
const encryption = require('../utils/encryption');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

function hiddenQuestion(query) {
  return new Promise(resolve => {
    process.stdout.write(query);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    
    let input = '';
    process.stdin.on('data', function(char) {
      char = char + '';
      
      switch (char) {
        case '\n':
        case '\r':
        case '\u0004':
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdout.write('\n');
          resolve(input);
          break;
        case '\u0003':
          process.exit();
          break;
        case '\u007f': // backspace
          if (input.length > 0) {
            input = input.slice(0, -1);
            process.stdout.write('\b \b');
          }
          break;
        default:
          input += char;
          process.stdout.write('*');
          break;
      }
    });
  });
}

async function createAdmin() {
  try {
    console.log('🔐 Creating Admin User for Forensic Analysis Platform');
    console.log('================================================');
    console.log('');
    
    // Connect to database
    await database.connect();
    
    // Check if admin already exists
    const existingAdmin = await database.get('SELECT id FROM users WHERE role = "admin"');
    if (existingAdmin) {
      console.log('⚠️  An admin user already exists.');
      const overwrite = await question('Do you want to create another admin user? (y/N): ');
      if (overwrite.toLowerCase() !== 'y' && overwrite.toLowerCase() !== 'yes') {
        console.log('Cancelled.');
        return;
      }
      console.log('');
    }
    
    // Get admin details
    const name = await question('First Name: ');
    if (!name.trim()) {
      throw new Error('First name is required');
    }
    
    const surname = await question('Last Name: ');
    if (!surname.trim()) {
      throw new Error('Last name is required');
    }
    
    let email;
    while (true) {
      email = await question('Email: ');
      if (!email.includes('@')) {
        console.log('Please enter a valid email address.');
        continue;
      }
      
      // Check if email already exists
      const existingUser = await database.get('SELECT id FROM users WHERE email = ?', [email]);
      if (existingUser) {
        console.log('A user with this email already exists.');
        continue;
      }
      break;
    }
    
    let password;
    while (true) {
      password = await hiddenQuestion('Password (min 8 chars, must include uppercase, lowercase, number, special char): ');
      
      if (password.length < 8) {
        console.log('Password must be at least 8 characters long.');
        continue;
      }
      
      if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/.test(password)) {
        console.log('Password must contain uppercase, lowercase, number and special character.');
        continue;
      }
      
      const confirmPassword = await hiddenQuestion('Confirm Password: ');
      if (password !== confirmPassword) {
        console.log('Passwords do not match.');
        continue;
      }
      break;
    }
    
    console.log('');
    console.log('Creating admin user...');
    
    // Generate RSA key pair for encryption
    const { publicKey, privateKey } = encryption.generateKeyPair();
    
    // Hash password
    const passwordHash = await encryption.hashPassword(password);
    
    // Create admin user
    const result = await database.run(`
      INSERT INTO users (name, surname, email, password_hash, role, verified, admin_approved, public_key, private_key)
      VALUES (?, ?, ?, ?, 'admin', TRUE, TRUE, ?, ?)
    `, [name.trim(), surname.trim(), email.toLowerCase(), passwordHash, publicKey, privateKey]);
    
    console.log('✅ Admin user created successfully!');
    console.log('');
    console.log('Admin Details:');
    console.log(`  ID: ${result.id}`);
    console.log(`  Name: ${name} ${surname}`);
    console.log(`  Email: ${email}`);
    console.log(`  Role: admin`);
    console.log('');
    console.log('You can now start the server and log in with these credentials.');
    
  } catch (error) {
    console.error('❌ Failed to create admin user:', error.message);
    process.exit(1);
  } finally {
    rl.close();
    await database.close();
  }
}

// Run if called directly
if (require.main === module) {
  createAdmin();
}

module.exports = createAdmin;