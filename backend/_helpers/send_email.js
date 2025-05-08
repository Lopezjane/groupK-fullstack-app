const nodemailer = require('nodemailer');
const config = require('config.json');

// Get the environment-specific configuration
const env = process.env.NODE_ENV || 'development';
const envConfig = config[env];

// Check if config exists for the current environment
if (!envConfig) {
    console.error(`No configuration found for environment: ${env}`);
    process.exit(1);
}

module.exports = sendEmail;

async function sendEmail({ to, subject, html, from = envConfig.emailFrom }) {
    try {
        const transporter = nodemailer.createTransport(envConfig.smtpOptions);
        
        // Verify connection configuration
        await transporter.verify();
        
        // Clean html content - remove potentially dangerous elements
        const safeHtml = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                             .replace(/javascript:/gi, 'removed:');
        
        // Extract plain text from HTML
        const plainText = safeHtml.replace(/<[^>]*>?/gm, '')
                               .replace(/\s+/g, ' ')
                               .trim();
        
        // Build the email with security headers
        const mailOptions = {
            from: {
                name: 'User-Management',
                address: from
            },
            to,
            subject,
            text: plainText,
            html: safeHtml,
            headers: {
                'X-Priority': '1',
                'X-MSMail-Priority': 'High',
                'Importance': 'High',
                'X-Mailer': 'User-Management Authentication System',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Strict-Transport-Security': 'max-age=31536000',
                'X-XSS-Protection': '1; mode=block'
            },
            // Accessibility and security additions
            contentType: 'text/html; charset=utf-8',
            dsn: {
                id: true,
                return: 'headers',
                notify: ['failure', 'delay'],
                recipient: from
            }
        };
        
        console.log(`Sending email to ${to} with subject "${subject}"`);
        const result = await transporter.sendMail(mailOptions);
        console.log(`Email sent successfully to ${to}. Message ID: ${result.messageId}`);
        return result;
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}