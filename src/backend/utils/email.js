const nodemailer = require('nodemailer');

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransporter({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  async sendVerificationCode(email, code) {
    const mailOptions = {
      from: process.env.FROM_EMAIL,
      to: email,
      subject: 'Email Verification - Forensic Analysis Platform',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Email Verification Required</h2>
          <p>Your verification code is:</p>
          <div style="background: #f4f4f4; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 3px; margin: 20px 0;">
            ${code}
          </div>
          <p>This code expires in 15 minutes.</p>
          <p>If you did not request this verification, please ignore this email.</p>
          <hr>
          <p style="color: #666; font-size: 12px;">
            ${process.env.APP_NAME || 'Forensic Analysis Platform'}<br>
            This is an automated message, please do not reply.
          </p>
        </div>
      `
    };

    return await this.transporter.sendMail(mailOptions);
  }

  async sendLoginCode(email, code) {
    const mailOptions = {
      from: process.env.FROM_EMAIL,
      to: email,
      subject: 'Login Verification - Forensic Analysis Platform',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Login Verification Required</h2>
          <p>Your login verification code is:</p>
          <div style="background: #f4f4f4; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 3px; margin: 20px 0;">
            ${code}
          </div>
          <p>This code expires in 10 minutes.</p>
          <p>If you did not attempt to log in, please secure your account immediately.</p>
          <hr>
          <p style="color: #666; font-size: 12px;">
            ${process.env.APP_NAME || 'Forensic Analysis Platform'}<br>
            This is an automated message, please do not reply.
          </p>
        </div>
      `
    };

    return await this.transporter.sendMail(mailOptions);
  }

  async testConnection() {
    try {
      await this.transporter.verify();
      console.log('✅ SMTP connection verified');
      return true;
    } catch (error) {
      console.error('❌ SMTP connection failed:', error.message);
      return false;
    }
  }
}

module.exports = new EmailService();
