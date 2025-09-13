const database = require('../database/connection');

async function auditLog({ userId = null, action, resourceType = null, resourceId = null, details = null, ipAddress = null }) {
  try {
    await database.run(`
      INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [userId, action, resourceType, resourceId, details, ipAddress]);
  } catch (error) {
    console.error('Audit log error:', error);
    // Don't throw error to avoid breaking main operation
  }
}

module.exports = { auditLog };
