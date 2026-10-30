
'use strict';

const express = require('express');
const crypto = require('node:crypto');

const app = express();

// --------------------------------------------------
// APPLICATION CONFIGURATION
// --------------------------------------------------

app.disable('x-powered-by');

const PORT = process.env.PORT || 3000;

// Support both the existing and Spring Boot property names
const VERIFY_TOKEN =
    process.env.WHATSAPP_WEBHOOK_VERIFY_TOKEN ||
    process.env.VERIFY_TOKEN;

const APP_SECRET =
    process.env.WHATSAPP_APP_SECRET ||
    process.env.APP_SECRET;


// --------------------------------------------------
// UTILITY METHODS
// --------------------------------------------------

function safeCompare(value1, value2) {
    if (typeof value1 !== 'string' ||
        typeof value2 !== 'string') {
        return false;
    }

    const buffer1 = Buffer.from(value1, 'utf8');
    const buffer2 = Buffer.from(value2, 'utf8');

    if (buffer1.length !== buffer2.length) {
        return false;
    }

    return crypto.timingSafeEqual(buffer1, buffer2);
}


// Verify Meta webhook signature using App Secret
function verifySignature(rawBody, signatureHeader) {

    if (!APP_SECRET) {
        console.error('WhatsApp App Secret is not configured');
        return false;
    }

    if (!signatureHeader ||
        !signatureHeader.startsWith('sha256=')) {
        return false;
    }

    const receivedSignature = signatureHeader.substring(7);

    if (!/^[a-fA-F0-9]{64}$/.test(receivedSignature)) {
        return false;
    }

    const expectedSignature = crypto
        .createHmac('sha256', APP_SECRET)
        .update(rawBody)
        .digest();

    const actualSignature = Buffer.from(
        receivedSignature,
        'hex'
    );

    return crypto.timingSafeEqual(
        expectedSignature,
        actualSignature
    );
}


// Mask mobile numbers in logs
function maskPhoneNumber(phoneNumber) {

    if (!phoneNumber) {
        return 'UNKNOWN';
    }

    const value = String(phoneNumber);

    if (value.length <= 4) {
        return '****';
    }

    return '******' + value.slice(-4);
}


// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get('/health', (req, res) => {

    return res.status(200).json({
        status: 'UP',
        application: 'Runam Teerchuko',
        service: 'WhatsApp Webhook',
        timestamp: new Date().toISOString()
    });

});


// --------------------------------------------------
// META WEBHOOK VERIFICATION - GET
// --------------------------------------------------

app.get('/', (req, res) => {

    console.log('Meta webhook verification request received');

    const mode = req.query['hub.mode'];
    const challenge = req.query['hub.challenge'];
    const token = req.query['hub.verify_token'];

    if (!VERIFY_TOKEN) {

        console.error(
            'WHATSAPP_WEBHOOK_VERIFY_TOKEN is not configured'
        );

        return res.status(500).send(
            'Webhook verification configuration missing'
        );
    }

    if (mode === 'subscribe' &&
        safeCompare(token, VERIFY_TOKEN)) {

        console.log('WEBHOOK VERIFIED SUCCESSFULLY');

        return res.status(200).send(challenge);
    }

    console.error('WEBHOOK VERIFICATION FAILED');

    return res.sendStatus(403);

});


// --------------------------------------------------
// WHATSAPP WEBHOOK - POST
// --------------------------------------------------

// IMPORTANT:
// Keep the original raw request body for signature validation.
// Do not put express.json() before this middleware.

app.post(
    '/',
    express.raw({
        type: 'application/json',
        limit: '2mb'
    }),
    (req, res) => {

        try {

            console.log('\n------------------------------------');
            console.log('WHATSAPP WEBHOOK EVENT RECEIVED');
            console.log('Time:', new Date().toISOString());
            console.log('------------------------------------');

            // Validate request body
            if (!Buffer.isBuffer(req.body)) {

                console.error('Invalid webhook request body');

                return res.sendStatus(400);
            }

            // Validate Meta request signature
            const signature = req.get(
                'x-hub-signature-256'
            );

            if (!verifySignature(req.body, signature)) {

                console.error(
                    'Invalid WhatsApp webhook signature'
                );

                return res.sendStatus(401);
            }

            // Parse JSON after signature validation
            const webhookData = JSON.parse(
                req.body.toString('utf8')
            );

            // Validate WhatsApp webhook object
            if (webhookData.object !==
                'whatsapp_business_account') {

                console.log('Unknown webhook object');

                return res.sendStatus(200);
            }

            // Process all webhook entries
            const entries = Array.isArray(webhookData.entry)
                ? webhookData.entry
                : [];

            entries.forEach(entry => {

                const changes = Array.isArray(entry.changes)
                    ? entry.changes
                    : [];

                changes.forEach(change => {

                    const value = change.value || {};

                    console.log(
                        'Webhook Field:',
                        change.field
                    );

                    // ----------------------------------
                    // WHATSAPP MESSAGES
                    // ----------------------------------

                    const messages = Array.isArray(value.messages)
                        ? value.messages
                        : [];

                    messages.forEach(message => {

                        console.log('\nINCOMING MESSAGE');

                        console.log({
                            from: maskPhoneNumber(message.from),
                            messageId: message.id,
                            timestamp: message.timestamp,
                            type: message.type
                        });

                        // Text message
                        if (message.type === 'text') {

                            console.log(
                                'Message type: TEXT'
                            );

                            console.log(
                                'Text message received'
                            );

                            // Add your incoming message processing
                            // logic here when required.
                        }

                        // Image message
                        else if (message.type === 'image') {

                            console.log(
                                'Message type: IMAGE'
                            );
                        }

                        // Document message
                        else if (message.type === 'document') {

                            console.log(
                                'Message type: DOCUMENT'
                            );
                        }

                        // Interactive message
                        else if (message.type === 'interactive') {

                            console.log(
                                'Message type: INTERACTIVE'
                            );
                        }

                        else {

                            console.log(
                                'Message type:',
                                message.type
                            );
                        }

                    });


                    // ----------------------------------
                    // MESSAGE DELIVERY STATUS
                    // ----------------------------------

                    const statuses = Array.isArray(value.statuses)
                        ? value.statuses
                        : [];

                    statuses.forEach(status => {

                        console.log('\nMESSAGE STATUS UPDATE');

                        console.log({
                            messageId: status.id,
                            recipient: maskPhoneNumber(
                                status.recipient_id
                            ),
                            status: status.status,
                            timestamp: status.timestamp
                        });

                        switch (status.status) {

                            case 'sent':

                                console.log(
                                    'WhatsApp message sent successfully'
                                );

                                break;

                            case 'delivered':

                                console.log(
                                    'WhatsApp message delivered successfully'
                                );

                                break;

                            case 'read':

                                console.log(
                                    'WhatsApp message read by recipient'
                                );

                                break;

                            case 'failed':

                                console.error(
                                    'WhatsApp message delivery failed'
                                );

                                if (status.errors) {

                                    console.error(
                                        'Delivery errors:',
                                        JSON.stringify(
                                            status.errors
                                        )
                                    );
                                }

                                break;

                            default:

                                console.log(
                                    'Other message status:',
                                    status.status
                                );

                        }

                    });

                });

            });

            console.log('\nWEBHOOK PROCESSED SUCCESSFULLY');
            console.log('------------------------------------\n');

            // Acknowledge successful webhook processing
            return res.sendStatus(200);

        } catch (error) {

            console.error(
                'WhatsApp webhook processing error:',
                error.message
            );

            return res.sendStatus(400);

        }

    }
);


// --------------------------------------------------
// ERROR HANDLING
// --------------------------------------------------

app.use((error, req, res, next) => {

    console.error(
        'Application error:',
        error.message
    );

    if (error.type === 'entity.too.large') {

        return res.status(413).json({
            status: 'ERROR',
            message: 'Webhook payload is too large'
        });

    }

    return res.status(400).json({
        status: 'ERROR',
        message: 'Invalid webhook request'
    });

});


// --------------------------------------------------
// START APPLICATION
// --------------------------------------------------

app.listen(PORT, '0.0.0.0', () => {

    console.log('\n======================================');
    console.log('RUNAM TEERCHUKO - WHATSAPP WEBHOOK');
    console.log('======================================');

    console.log('Server Port:', PORT);

    console.log(
        'Verify Token Configured:',
        Boolean(VERIFY_TOKEN)
    );

    console.log(
        'App Secret Configured:',
        Boolean(APP_SECRET)
    );

    console.log('Server Status: RUNNING');

    console.log('======================================\n');

});
