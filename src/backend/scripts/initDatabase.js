require('dotenv').config();
const database = require('../database/connection');
const emailService = require('../utils/email');

async function initDatabase() {
  try {
    console.log('🔧 Initializing Forensic Analysis Platform Database...');
    
    // Connect to database
    await database.connect();
    
    // Initialize schema
    await database.initializeSchema();
    
    // Test email connection
    console.log('📧 Testing email configuration...');
    const emailWorking = await emailService.testConnection();
    
    if (!emailWorking) {
      console.warn('⚠️  Warning: Email service is not configured properly. Email notifications will not work.');
    }
    
    console.log('✅ Database initialization completed successfully!');
    console.log('');
    console.log('Next steps:');
    console.log('1. Run "npm run create-admin" to create an admin user');
    console.log('2. Start the server with "npm start" or "npm run dev"');
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
  } finally {
    await database.close();
  }
}

// Run if called directly
if (require.main === module) {
  initDatabase();
}

module.exports = initDatabase;