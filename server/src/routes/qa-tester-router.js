const express = require('express');
const path = require('path');

module.exports = function(transporter) {
    const router = express.Router();

    // Serve the QA signup page
    router.get('/', (req, res) => {
        res.sendFile(path.join(__dirname, 'qa-signup.html'));
    });

    // Handle QA tester signup submission
    router.post('/submit', async (req, res) => {
        const { email, name, experience } = req.body;

        // Basic validation
        if (!email || !email.includes('@')) {
            return res.status(400).json({ 
                success: false, 
                message: 'Please provide a valid email address' 
            });
        }

        try {
            // Email content
            const mailOptions = {
                from: process.env.SMTP_USER,
                to: 'thelivingconnect@gmail.com',
                subject: 'New QA Tester Signup',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #0f1419; color: #e0e6ed; padding: 20px; border-radius: 10px;">
                        <div style="background: linear-gradient(135deg, #1a2332 0%, #0f1419 100%); padding: 30px; border-radius: 8px; border-left: 4px solid #fbbf24;">
                            <h2 style="color: #fbbf24; margin-top: 0; font-size: 24px;">🎯 New QA Tester Application</h2>
                            
                            <div style="background-color: #1a2332; padding: 20px; border-radius: 6px; margin: 20px 0;">
                                <p style="margin: 10px 0; font-size: 16px;">
                                    <strong style="color: #fbbf24;">Name:</strong> 
                                    <span style="color: #e0e6ed;">${name || 'Not provided'}</span>
                                </p>
                                <p style="margin: 10px 0; font-size: 16px;">
                                    <strong style="color: #fbbf24;">Email:</strong> 
                                    <span style="color: #e0e6ed;">${email}</span>
                                </p>
                                <p style="margin: 10px 0; font-size: 16px;">
                                    <strong style="color: #fbbf24;">Testing Experience:</strong> 
                                    <span style="color: #e0e6ed;">${experience || 'Not provided'}</span>
                                </p>
                            </div>
                            
                            <p style="color: #9ca3af; font-size: 14px; margin-top: 20px; border-top: 1px solid #2d3748; padding-top: 15px;">
                                Submitted on: ${new Date().toLocaleString()}
                            </p>
                        </div>
                    </div>
                `,
                text: `
New QA Tester Signup

Name: ${name || 'Not provided'}
Email: ${email}
Testing Experience: ${experience || 'Not provided'}

Submitted on: ${new Date().toLocaleString()}
                `
            };

            // Send email
            await transporter.sendMail(mailOptions);

            res.json({ 
                success: true, 
                message: 'Thank you for signing up! We\'ll be in touch soon.' 
            });

        } catch (error) {
            console.error('QA signup email error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Failed to submit application. Please try again later.' 
            });
        }
    });

    return router;
};
