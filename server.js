import express from "express";
import axios from "axios";
import * as crypto from "crypto";
import bodyParser from "body-parser";

import "dotenv/config";

import {
  completePaymentRequest,
  getCheckoutById,
  getPaymentRequest,
  getTransactionById,
} from "./vivenu.js";

const app = express();
const port = process.env.PORT || 8080;

app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf.toString();
    },
  })
);
app.use(bodyParser.urlencoded({ extended: true }));

const APP_URL = process.env.APP_URL;
const STRAUMUR_API_KEY = process.env.STRAUMUR_API_KEY;
const STRAUMUR_TERMINAL_ID = process.env.STRAUMUR_TERMINAL_ID;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const SELLER_CURRENCY = process.env.CURRENCY;
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;

async function initializeTransaction(
  customerEmail,
  amount,
  paymentId,
  callbackUrl,
  cancelUrl,
  currency
) {
  const url = "https://greidslugatt.straumur.is/api/v1/hostedcheckout";

  const fields = {
    amount: Math.round(amount),
    currency: currency || SELLER_CURRENCY || "ISK",
    returnUrl: callbackUrl,
    reference: paymentId,
    abandonUrl: "https://www.moment.is/",
    terminalIdentifier: STRAUMUR_TERMINAL_ID,
  };

  try {
    const response = await axios.post(url, fields, {
      headers: {
        "X-API-key": `${STRAUMUR_API_KEY}`,
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
      },
    });

    return {
      success: true,
      data: response.data.url,
      checkoutReference: response.data.checkoutReference,
    };
  } catch (error) {
    console.error(
      "Error initializing Straumur transaction:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

async function getStraumurCheckoutStatus(checkoutReference) {
  const url = `https://greidslugatt.straumur.is/api/v1/hostedcheckout/status/${checkoutReference}`;

  const headers = {
    "X-API-key": `${STRAUMUR_API_KEY}`,
    "Cache-Control": "no-cache",
    "Content-Type": "application/json",
  };

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    console.error(
      "Error getting Straumur checkout status:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

/**
 * Create a refund for a transaction (partial or full)
 * @param {string} merchantReference - Merchant reference to uniquely identify a payment
 * @param {string} payfacReference - Straumur reference to uniquely identify a payment
 * @param {number} amount - The amount to be refunded in minor units
 * @param {string} currency - The three-character ISO currency code (e.g., "ISK")
 * @param {string} refundReason - Optional reason for refund (OTHER, RETURN, DUPLICATE, FRAUD, CUSTOMER REQUEST)
 * @returns {Promise<Object>} Refund response
 */
async function createStraumurRefund(
  merchantReference,
  payfacReference,
  amount,
  currency = "ISK",
  refundReason = null
) {
  const url = "https://greidslugatt.straumur.is/api/v1/modification/refund";

  const data = {
    reference: merchantReference,
    payfacReference: payfacReference,
    amount: amount,
    currency: currency,
  };

  // Add refund reason if provided and valid
  const validRefundReasons = [
    "OTHER",
    "RETURN",
    "DUPLICATE",
    "FRAUD",
    "CUSTOMER REQUEST",
  ];
  if (refundReason && validRefundReasons.includes(refundReason)) {
    data.refundReason = refundReason;
  }

  const headers = {
    "X-API-key": `${STRAUMUR_API_KEY}`,
    "Content-Type": "application/json",
    "Cache-Control": "no-cache",
  };

  try {
    const response = await axios.post(url, data, { headers });
    console.log("Straumur refund created successfully:", response.data);
    return {
      success: true,
      data: response.data,
    };
  } catch (error) {
    console.error(
      "Error creating Straumur refund:",
      error.response ? error.response.data : error.message
    );
    return {
      success: false,
      error: error.response ? error.response.data : error.message,
    };
  }
}

// Test function to verify our implementation matches Straumur's example
function testStraumurExample() {
  console.log("=== TESTING STRAUMUR EXAMPLE ===");

  // Straumur's documented example
  const testPayload = {
    checkoutReference: null,
    payfacReference: "21135253156",
    merchantReference: "9990QQAZ1221",
    amount: "48900",
    currency: "ISK",
    reason: null,
    success: "true",
  };

  const testSecret =
    "4eab969bd65a39c17c906dfcef1fe69d481716b0845a6c0892284cf9c06e4314";
  const expectedSignature = "oH4Sgo4cZ/O8489HQU7TbcvohJkH4eHbz50Q3G+VXfk=";

  console.log("Test payload:", testPayload);
  console.log("Test secret:", testSecret);
  console.log("Expected signature:", expectedSignature);

  // Show the exact payload string that should be signed
  const expectedPayloadString =
    "null:21135253156:9990QQAZ1221:48900:ISK:null:true";
  console.log("Expected payload string:", expectedPayloadString);

  // Test our implementation
  const calculatedSignatures = calculateStraumurHMAC(testSecret, testPayload);
  console.log("Our calculated signature (base64):", calculatedSignatures);
  console.log(
    "Matches expected (base64):",
    calculatedSignatures.base64 === expectedSignature
  );

  // If it doesn't match, let's debug the payload construction
  if (calculatedSignatures !== expectedSignature) {
    console.log("=== DEBUGGING PAYLOAD CONSTRUCTION ===");
    const ourPayloadString = [
      testPayload.checkoutReference ?? "null",
      testPayload.payfacReference ?? "null",
      testPayload.merchantReference ?? "null",
      testPayload.amount ?? "null",
      testPayload.currency ?? "null",
      testPayload.reason ?? "null",
      testPayload.success ?? "null",
    ].join(":");
    console.log("Our payload string:", ourPayloadString);
    console.log(
      "Payload strings match:",
      ourPayloadString === expectedPayloadString
    );
    console.log("==================================");
  }

  console.log("==================================");
}

function hexToBytes(hex) {
  if (hex.length % 2 === 1) hex += "0";
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function b64ToBytes(b64) {
  try {
    return Buffer.from(b64.trim(), "base64");
  } catch {
    return null;
  }
}

function utf8ToBytes(s) {
  return Buffer.from((s ?? "").trim(), "utf8");
}
function hmacBase64(keyBytes, payloadString) {
  return crypto
    .createHmac("sha256", keyBytes)
    .update(Buffer.from(payloadString, "utf8"))
    .digest("base64");
}

function calculateStraumurHMAC(webhookSecretHex, payload) {
  // EXACT C# ORDER:
  // CheckoutReference, PayfacReference, MerchantReference, Amount, Currency, Reason, Success
  const signaturePayload = [
    payload.checkoutReference ?? "",
    payload.payfacReference ?? "",
    payload.merchantReference ?? "",
    payload.amount ?? "",
    payload.currency ?? "",
    payload.reason ?? "",
    payload.success ?? "",
  ].join(":");

  const binaryKey = hexToBytes(webhookSecretHex); // hex key → bytes
  const binaryPayload = Buffer.from(signaturePayload, "utf8"); // string → UTF-8 bytes

  const base64 = crypto
    .createHmac("sha256", binaryKey)
    .update(binaryPayload)
    .digest("base64");
  const hex = crypto
    .createHmac("sha256", binaryKey)
    .update(binaryPayload)
    .digest("hex");

  console.log("=== DEBUG: PAYLOAD CONSTRUCTION ===");
  console.log(
    "Field order used: CheckoutReference, PayfacReference, MerchantReference, Amount, Currency, Reason, Success"
  );
  console.log("Final payload string:", signaturePayload);
  console.log("Payload length:", signaturePayload.length);
  console.log("==================================");

  return { base64, hex, payloadString: signaturePayload };
}

app.get("/pay/callback", async (req, res) => {
  try {
    const paymentId = req.query.paymentId;
    const paymentRequest = await getPaymentRequest(paymentId);

    if (paymentRequest && paymentRequest.status !== "NEW") {
      console.error("payment request is already processed");
      return res.status(403).end();
    }

    console.log("Payment Request Received => ", paymentRequest);

    const details = await initializeTransaction(
      paymentRequest.customer.email,
      paymentRequest.amount * 100,
      paymentId,
      `${APP_URL}/straumur/callback?paymentRequestId=${paymentId}`,
      `${APP_URL}/straumur/callback?paymentRequestId=${paymentId}`,
      paymentRequest.currency
    );

    if (details && details.success) {
      res.redirect(details.data);
      res.end();
    } else {
      res.status(404).send("Payment processing error", details);
    }
  } catch (error) {
    console.error("Error processing payment:", error);
    res.status(500).send("Error processing payment");
  }
});

app.get("/straumur/callback", async (req, res) => {
  try {
    let paymentId = req.query.paymentRequestId;

    let checkoutReference = req.query.checkoutReference;

    const paymentRequest = await getPaymentRequest(paymentId);

    if (paymentRequest.status !== "NEW") {
      console.error("Payment request is already processed");

      if (paymentRequest.status === "SUCCEEDED") {
        return res.redirect(paymentRequest.successReturnUrl);
      } else {
        return res.redirect(paymentRequest.failureReturnUrl);
      }
    }

    const checkoutStatus = await getStraumurCheckoutStatus(checkoutReference);

    console.log("STRAUMUR CHECKOUT STATUS:", checkoutStatus);

    console.log("STRAUMUR callback received for paymentId:", paymentId);

    if (checkoutStatus.status === "Completed") {
      await completePaymentRequest(paymentId);
      return res.redirect(paymentRequest.successReturnUrl);
    }

    return res.redirect(paymentRequest.failureReturnUrl);
  } catch (e) {
    console.error("Error handling Straumur callback:", e);
    return res.status(500).send("Error handling Straumur callback");
  }
});

app.post("/webhook", async (req, res) => {
  try {
    // Check if webhook secret is configured
    if (!WEBHOOK_SECRET) {
      console.error("WEBHOOK_SECRET not configured");
      return res.status(500).send("Webhook secret not configured");
    }

    const payload = req.body;

    console.log("WEBHOOK RECEIVED", req.body);

    // Extract the specific fields in the exact order required by Straumur
    const {
      checkoutReference,
      merchantReference,
      reason,
      success,
      hmacSignature,
      additionalData,
    } = payload;

    // Validate HMAC signature from payload body
    if (!hmacSignature) {
      console.log("Missing HMAC signature in webhook payload");
      return res.status(400).send("Missing HMAC signature");
    }

    // Calculate HMAC signature using the helper function
    const calculatedSignatures = calculateStraumurHMAC(WEBHOOK_SECRET, payload);

    // Check if received signature matches either format
    const signaturesMatch = hmacSignature === calculatedSignatures.base64;

    if (!signaturesMatch) {
      console.log("Invalid HMAC signature in webhook");
      console.log("Expected (base64):", calculatedSignatures.base64);

      console.log("Received:", hmacSignature);
      console.log("Full payload received:", JSON.stringify(payload, null, 2));
      return res.status(403).send("Invalid HMAC signature");
    }

    console.log("HMAC signature validated successfully");

    const eventType = additionalData?.eventType;
    const paymentId = merchantReference || checkoutReference;

    console.log(
      `STRAUMUR WEBHOOK RECEIVED - Event: ${eventType}, Payment ID: ${paymentId}, Success: ${success}`
    );

    if (!paymentId) {
      console.log("No payment reference found in webhook payload");
      return res.status(400).send("No payment reference found");
    }

    // Get payment request
    const paymentRequest = await getPaymentRequest(paymentId);
    if (!paymentRequest) {
      console.log(`Payment request not found for ID: ${paymentId}`);
      return res.status(404).send("Payment request not found");
    }

    if (paymentRequest && paymentRequest.status === "SUCCEEDED") {
      console.log("Payment request already completed");
      return res.status(200).send("Payment request already completed");
    }

    // Handle different event types
    switch (eventType) {
      case "Authorization":
        if (success === "true") {
          console.log(`Authorization successful for payment: ${paymentId}`);
          // Complete the payment request
          await completePaymentRequest(paymentId);
        }
        break;

      case "Capture":
        if (success === "true") {
          // Complete the payment request
          await completePaymentRequest(paymentId);
        } else {
          console.error(
            `Capture failed for payment: ${paymentId}, Reason: ${reason}`
          );
          // Handle failed capture
        }
        break;

      default:
        console.warn(
          `Unknown event type: ${eventType} for payment: ${paymentId}`
        );
        break;
    }

    // Log additional data for debugging
    if (additionalData) {
      console.log("Additional webhook data:", {
        eventType: additionalData.eventType,
        cardUsage: additionalData.cardUsage,
        paymentMethod: additionalData.paymentMethod,
        cardSummary: additionalData.cardSummary,
        authCode: additionalData.authCode,
        threeDAuthenticated: additionalData.threeDAuthenticated,
      });
    }

    return res.status(200).send("Webhook processed successfully");
  } catch (error) {
    console.error("Error processing Straumur webhook:", error);
    return res.status(500).send("Error processing webhook");
  }
});

app.post("/payment/refund", async (req, res) => {
  try {
    const payload = req.body;

    if (payload.type !== "payment.refund") {
      return res.status(400).send("unsupported type");
    }

    const signature = crypto
      .createHmac("sha256", GATEWAY_SECRET)
      .update(req.rawBody)
      .digest("hex");

    const requestSignature = req.headers["x-vivenu-signature"];
    const isValid = signature.toLowerCase() === requestSignature.toLowerCase();
    if (!isValid) {
      return res.status(400).send("invalid signature");
    }

    console.log("PAYLOAD => ", payload);
    // Extract refund details from the payload
    const {
      merchantReference,
      psp,
      amount,
      currency = "ISK",
      refundReason,
      transactionId,
    } = payload.data;

    const transactionDetails = await getTransactionById(transactionId);

    const checkoutId = transactionDetails.checkoutId;

    const checkoutDetails = await getCheckoutById(checkoutId);

    const paymentRequestId =
      checkoutDetails.docs[0] && checkoutDetails.docs[0].paymentRequestId;

    const checkoutStatus = await getStraumurCheckoutStatus(paymentRequestId);

    console.log("CHECKOUT STATUS => ", checkoutStatus);

    if (!currency || !psp || !amount) {
      return res.status(400).send("Missing required refund parameters");
    }

    // Create refund using Straumur API
    const refundResult = await createStraumurRefund(
      paymentRequestId,
      psp,
      amount,
      currency,
      refundReason
    );

    if (refundResult.success) {
      console.log("Refund processed successfully:", refundResult.data);
      return res.status(200).json({
        success: true,
        data: refundResult.data,
      });
    } else {
      console.error("Refund failed:", refundResult.error);
      return res.status(500).json({
        success: false,
        error: refundResult.error,
      });
    }
  } catch (e) {
    console.error("Error handling Refund:", e);
    return res.status(500).json({
      success: false,
      error: e.message,
    });
  }
});

app.get("/", async (req, res) => {
  res.send("API RUNNING FOR MERCHANT => ");
});

app.listen(port, () => {
  console.log(`Listening at http://localhost:${port}`);

  // Test our HMAC implementation against Straumur's documented example
  testStraumurExample();
});
