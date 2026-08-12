const nodemailer = require('nodemailer');

const isConfigured = () => {
  return !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
};

const transporter = isConfigured()
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '465', 10),
      secure: parseInt(process.env.SMTP_PORT || '465', 10) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    })
  : null;

async function sendPasswordResetEmail(to, resetUrl) {
  if (!transporter) {
    throw new Error('SMTP is not configured. Set SMTP_HOST, SMTP_USER and SMTP_PASS in .env');
  }
  await transporter.sendMail({
    from: process.env.SMTP_FROM || 'BISECO E-Vote <no-reply@biseco.local>',
    to,
    subject: 'BISECO Admin Password Reset',
    text:
      'You requested a password reset for the BISECO E-Vote admin account.\n\n' +
      'Click the link below to set a new password (valid for 1 hour):\n\n' +
      resetUrl +
      '\n\n' +
      'If you did not request this, you can safely ignore this email.\n',
    html:
      '<p>You requested a password reset for the <strong>BISECO E-Vote</strong> admin account.</p>' +
      '<p>Click the button below to set a new password. The link is valid for <strong>1 hour</strong>.</p>' +
      '<p style="text-align:center;"><a href="' +
      resetUrl +
      '" style="display:inline-block;padding:12px 24px;background:#0044cc;color:#fff;text-decoration:none;border-radius:6px;font-weight:bold;">Reset Password</a></p>' +
      '<p>If the button does not work, copy and paste this link into your browser:<br>' +
      '<a href="' +
      resetUrl +
      '">' +
      resetUrl +
      '</a></p>' +
      '<p>If you did not request this, you can safely ignore this email.</p>',
  });
}

module.exports = { sendPasswordResetEmail, isConfigured };
