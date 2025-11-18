# Gateway Straumur

This is a payment gateway integration using the Straumur Hosted Checkout API.

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```bash
# Straumur API Configuration
STRAUMUR_API_KEY=your_straumur_api_key_here
STRAUMUR_TERMINAL_ID=your_terminal_identifier_here
WEBHOOK_SECRET=your_hex_encoded_webhook_secret_here

# App Configuration
APP_URL=http://localhost:8080
PORT=8080

# Currency
CURRENCY=ISK

# Gateway Secret (for webhook validation)
GATEWAY_SECRET=your_gateway_secret_here
```

**Note**: The `WEBHOOK_SECRET` should be a hex-encoded string (e.g., `4eab969bd65a39c17c906dfcef1fe69d481716b0845a6c0892284cf9c06e4314`) as used by Straumur's HMAC signature validation.

## Troubleshooting

### Webhook Signature Validation Issues

If you're experiencing HMAC signature validation failures:

1. **Verify Webhook Secret**: Ensure your `WEBHOOK_SECRET` matches exactly what Straumur provided
2. **Check Secret Format**: The secret should be a hex-encoded string (64 characters for 32-byte key)
3. **Contact Straumur**: If signatures still don't match, contact Straumur support to verify:
   - The correct webhook secret
   - The exact signature calculation method
   - Any additional requirements for webhook validation

### Common Issues

- **Wrong Secret**: Using API key instead of webhook secret
- **Secret Format**: Secret might be base64, raw string, or different encoding
- **Algorithm Mismatch**: Straumur might use different hashing algorithm than SHA256
- **Payload Format**: Subtle differences in field ordering or encoding

## Straumur API Integration

This application has been updated to use the Straumur Hosted Checkout API instead of the previous startbutton API.

### Key Changes Made:

1. **Transaction Initialization**: Now uses `https://checkout-api.staging.straumur.is/api/v1/hostedcheckout`
2. **Checkout Status**: Added function to check checkout status using Straumur's API
3. **Refunds**: Updated to use Straumur's refund endpoint
4. **Webhooks**: Comprehensive webhook handling for all Straumur event types
5. **Callbacks**: Updated callback URLs to use `/straumur/callback` instead of `/paystack/callback`

### API Endpoints:

- `POST /pay/callback` - Initialize a new payment transaction
- `GET /straumur/callback` - Handle payment completion callback
- `POST /webhook` - Handle Straumur webhooks with event type processing
- `POST /straumur/refund` - Process refunds

### Webhook Event Types

The webhook endpoint handles all Straumur event types as documented in their [webhook documentation](https://straumur-documentation.vercel.app/webhooks/webhook-message):

1. **Authorization** - Funds are reserved from customer's account
2. **Capture** - Authorized funds are withdrawn from customer's account
3. **Adjustment** - Modification to authorized amount (increase/decrease)
4. **Refund** - Refund processing notification
5. **Tokenization** - Payment token creation for future payments

### Webhook Security

- **HMAC Signature Validation**: All webhooks are validated using HMAC-SHA256 signatures following Straumur's specific requirements
- **Ordered Payload Validation**: Signature calculation uses the exact field order: CheckoutReference, PayfacReference, MerchantReference, Amount, Currency, Reason, Success
- **Event Type Processing**: Different logic for each event type
- **Payment Status Updates**: Automatic payment completion on successful capture events
- **Comprehensive Logging**: Detailed logging for debugging and monitoring
- **Helper Functions**: Dedicated function for HMAC signature calculation and validation

### Required Straumur Configuration:

1. **API Key**: Your Straumur API key for authentication
2. **Terminal Identifier**: Your 12-character terminal identifier from the Merchant Portal
3. **Currency**: Default currency (ISK recommended for Icelandic payments)
4. **Webhook URL**: Configure your webhook endpoint in Straumur's Merchant Portal

## Getting Started

1. Install dependencies: `npm install`
2. Set up environment variables
3. Configure webhook endpoint in Straumur Merchant Portal
4. Run the server: `npm start`

## Notes

- The staging API endpoint is used by default. For production, update the URL to the production endpoint.
- Webhook validation is implemented using HMAC-SHA256 signatures for security.
- Transaction reference storage needs to be implemented based on your specific data model.
- The webhook endpoint automatically handles payment completion on successful capture events.
