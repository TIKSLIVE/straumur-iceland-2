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
  }),
);
app.use(bodyParser.urlencoded({ extended: true }));

const APP_URL = process.env.APP_URL;
const STRAUMUR_API_KEY = process.env.STRAUMUR_API_KEY;
const STRAUMUR_TERMINAL_ID = process.env.STRAUMUR_TERMINAL_ID;
const STRAUMUR_BASE_URL = "https://greidslugatt.straumur.is/api/v1";
const STRAUMUR_PATHS = {
  hostedCheckout: `${STRAUMUR_BASE_URL}/hostedcheckout`,
  checkoutStatus: `${STRAUMUR_BASE_URL}/hostedcheckout/status`,
  refund: `${STRAUMUR_BASE_URL}/modification/refund`,
};
// All HMAC keys to try for webhook validation (env WEBHOOK_SECRET + array; first match wins)
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET?.trim() || "";
const DEFAULT_HMAC_KEYS = [
  ...(WEBHOOK_SECRET ? [WEBHOOK_SECRET] : []),
  "04d69fb95b33d185340bd5993d189d81b45d1c7efceee28d97", // prod
  "037c16ab5f9cc4db9beee380a1f5ddf05f601a727d5ce953",
  "60174178b7e7996f0b714459b137d4990f9cafc19cab6a60",
  "2b7fe6a6f1d64d6bdf3513f086861209fcc9cf2a1348b7d3",
].filter((k) => k && /^[0-9a-fA-F]+$/.test(String(k).trim()));
const SELLER_CURRENCY = process.env.CURRENCY;
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;

function toEnvKeySegment(value) {
  return String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .toUpperCase();
}

function getSellerCredentials(sellerId) {
  const envSegment = toEnvKeySegment(sellerId);
  const sellerWebhookSecret =
    process.env[`WEBHOOK_SECRET_${envSegment}`]?.trim() || "";
  const hmacKeys = [
    ...(sellerWebhookSecret ? [sellerWebhookSecret] : []),
    ...DEFAULT_HMAC_KEYS,
  ].filter((k) => k && /^[0-9a-fA-F]+$/.test(String(k).trim()));

  return {
    apiKey: process.env[`API_KEY_${envSegment}`] || process.env.API_KEY,
    gatewaySecret:
      process.env[`GATEWAY_SECRET_${envSegment}`] || GATEWAY_SECRET,
    straumurApiKey: STRAUMUR_API_KEY,
    terminalIdentifier: STRAUMUR_TERMINAL_ID,
    hmacKeys,
  };
}

function getStraumurHeaders(straumurApiKey) {
  return {
    "X-API-key": `${straumurApiKey}`,
    "Content-Type": "application/json",
    "Cache-Control": "no-cache",
  };
}

function logAxiosError(prefix, error) {
  console.error(prefix, error.response ? error.response.data : error.message);
}

async function initializeTransaction(
  amount,
  paymentId,
  callbackUrl,
  currency,
  straumurApiKey,
  terminalIdentifier,
) {
  const fields = {
    amount: Math.round(amount),
    currency: currency || SELLER_CURRENCY || "ISK",
    returnUrl: callbackUrl,
    reference: paymentId,
    terminalIdentifier,
  };

  try {
    const response = await axios.post(STRAUMUR_PATHS.hostedCheckout, fields, {
      headers: getStraumurHeaders(straumurApiKey),
    });

    return {
      success: true,
      data: response.data.url,
      checkoutReference: response.data.checkoutReference,
    };
  } catch (error) {
    logAxiosError("Error initializing Straumur transaction:", error);
    throw error;
  }
}

async function getStraumurCheckoutStatus(checkoutReference, straumurApiKey) {
  try {
    const response = await axios.get(
      `${STRAUMUR_PATHS.checkoutStatus}/${checkoutReference}`,
      { headers: getStraumurHeaders(straumurApiKey) },
    );
    return response.data;
  } catch (error) {
    logAxiosError("Error getting Straumur checkout status:", error);
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
  refundReason = null,
  straumurApiKey,
) {
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

  try {
    const response = await axios.post(STRAUMUR_PATHS.refund, data, {
      headers: getStraumurHeaders(straumurApiKey),
    });
    console.log("Straumur refund created successfully:", response.data);
    return {
      success: true,
      data: response.data,
    };
  } catch (error) {
    logAxiosError("Error creating Straumur refund:", error);
    return {
      success: false,
      error: error.response ? error.response.data : error.message,
    };
  }
}

/** Match working Straumur JS example: hex key → bytes (odd length padded with "0") */
function convertHexToByteArray(hex) {
  if (hex.length % 2 === 1) hex += "0";
  return Buffer.from(hex, "hex");
}

function buildSignaturePayload(payload, fieldOrder) {
  const get = (obj, ...keys) => {
    for (const k of keys) {
      const v = obj?.[k];
      if (v != null) return String(v);
    }
    return "";
  };
  return fieldOrder.map((keys) => get(payload, ...keys)).join(":");
}

/** Supported field orders: documented C# order vs webhook JSON order (success before reason) */
const SIGNATURE_FIELD_ORDERS = {
  documented: [
    ["checkoutReference", "CheckoutReference"],
    ["payfacReference", "PayfacReference"],
    ["merchantReference", "MerchantReference"],
    ["amount", "Amount"],
    ["currency", "Currency"],
    ["reason", "Reason"],
    ["success", "Success"],
  ],
  webhookOrder: [
    ["payfacReference", "PayfacReference"],
    ["merchantReference", "MerchantReference"],
    ["checkoutReference", "CheckoutReference"],
    ["amount", "Amount"],
    ["currency", "Currency"],
    ["success", "Success"],
    ["reason", "Reason"],
  ],
};

function calculateStraumurHMAC(webhookSecretHex, payload) {
  const binaryKey = convertHexToByteArray(webhookSecretHex);

  const results = {};
  for (const [name, order] of Object.entries(SIGNATURE_FIELD_ORDERS)) {
    const signaturePayload = buildSignaturePayload(payload, order);
    const binaryPayload = Buffer.from(signaturePayload, "utf8");
    results[name] = {
      base64: crypto
        .createHmac("sha256", binaryKey)
        .update(binaryPayload)
        .digest("base64"),
      hex: crypto
        .createHmac("sha256", binaryKey)
        .update(binaryPayload)
        .digest("hex"),
      payloadString: signaturePayload,
    };
  }

  console.log("=== DEBUG: PAYLOAD CONSTRUCTION ===");
  console.log("Documented order payload:", results.documented.payloadString);
  console.log("Webhook order payload:  ", results.webhookOrder.payloadString);
  console.log("==================================");

  return results;
}

function validateStraumurWebhookSignature(payload, hmacSignature, hmacKeys) {
  let lastCalculated = null;

  for (let i = 0; i < hmacKeys.length; i++) {
    const trimmedKey = hmacKeys[i].trim();
    const calculated = calculateStraumurHMAC(trimmedKey, payload);
    lastCalculated = calculated;

    const matchDocumented = hmacSignature === calculated.documented.base64;
    const matchWebhookOrder = hmacSignature === calculated.webhookOrder.base64;

    if (matchDocumented || matchWebhookOrder) {
      return {
        validated: true,
        matchedWebhookOrderOnly: matchWebhookOrder && !matchDocumented,
        keyIndex: i,
      };
    }
  }

  return {
    validated: false,
    lastCalculated,
  };
}

function requireSellerCredentials(req, res) {
  const { sellerId } = req.params;
  if (!sellerId) {
    res.status(400).send("Missing sellerId");
    return null;
  }

  const credentials = getSellerCredentials(sellerId);
  if (!credentials.apiKey) {
    res.status(500).send(`Missing API key for seller ${sellerId}`);
    return null;
  }
  if (!credentials.gatewaySecret) {
    res.status(500).send(`Missing gateway secret for seller ${sellerId}`);
    return null;
  }
  if (!credentials.straumurApiKey) {
    res.status(500).send(`Missing Straumur API key for seller ${sellerId}`);
    return null;
  }
  if (!credentials.terminalIdentifier) {
    res.status(500).send(`Missing terminal ID for seller ${sellerId}`);
    return null;
  }
  if (!credentials.hmacKeys.length) {
    res.status(500).send(`Missing webhook secret for seller ${sellerId}`);
    return null;
  }

  return { sellerId, credentials };
}

app.get("/:sellerId/pay/callback", async (req, res) => {
  try {
    const sellerContext = requireSellerCredentials(req, res);
    if (!sellerContext) return;
    const { sellerId, credentials } = sellerContext;

    const paymentId = req.query.paymentId;
    const paymentRequest = await getPaymentRequest(
      paymentId,
      credentials.apiKey,
    );

    if (paymentRequest && paymentRequest.status !== "NEW") {
      console.error("payment request is already processed");
      return res.status(403).end();
    }

    console.log("Payment Request Received => ", paymentRequest);

    const details = await initializeTransaction(
      paymentRequest.amount * 100,
      paymentId,
      `${APP_URL}/${sellerId}/straumur/callback?paymentRequestId=${paymentId}`,
      paymentRequest.currency,
      credentials.straumurApiKey,
      credentials.terminalIdentifier,
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

app.get("/:sellerId/straumur/callback", async (req, res) => {
  try {
    const sellerContext = requireSellerCredentials(req, res);
    if (!sellerContext) return;
    const { credentials } = sellerContext;

    let paymentId = req.query.paymentRequestId;

    let checkoutReference = req.query.checkoutReference;

    const paymentRequest = await getPaymentRequest(
      paymentId,
      credentials.apiKey,
    );

    if (paymentRequest.status !== "NEW") {
      console.error("Payment request is already processed");

      if (paymentRequest.status === "SUCCEEDED") {
        return res.redirect(paymentRequest.successReturnUrl);
      } else {
        return res.redirect(paymentRequest.failureReturnUrl);
      }
    }

    const checkoutStatus = await getStraumurCheckoutStatus(
      checkoutReference,
      credentials.straumurApiKey,
    );

    console.log("STRAUMUR CHECKOUT STATUS:", checkoutStatus);

    console.log("STRAUMUR callback received for paymentId:", paymentId);

    if (checkoutStatus.status === "Completed") {
      await completePaymentRequest(
        paymentId,
        credentials.apiKey,
        credentials.gatewaySecret,
      );
      return res.redirect(paymentRequest.successReturnUrl);
    }

    return res.redirect(paymentRequest.failureReturnUrl);
  } catch (e) {
    console.error("Error handling Straumur callback:", e);
    return res.status(500).send("Error handling Straumur callback");
  }
});

app.post("/:sellerId/webhook", async (req, res) => {
  try {
    const sellerContext = requireSellerCredentials(req, res);
    if (!sellerContext) return;
    const { credentials } = sellerContext;

    const payload = req.body;

    const {
      checkoutReference,
      merchantReference,
      reason,
      success,
      hmacSignature,
      additionalData,
    } = payload;

    if (!hmacSignature) {
      console.error("Missing HMAC signature in webhook payload");
      return res.status(400).send("Missing HMAC signature");
    }

    const signatureResult = validateStraumurWebhookSignature(
      payload,
      hmacSignature,
      credentials.hmacKeys,
    );

    if (signatureResult.validated && signatureResult.matchedWebhookOrderOnly) {
      console.log(
        `HMAC matched using webhook field order (key index ${signatureResult.keyIndex})`,
      );
    }

    if (!signatureResult.validated) {
      console.error(
        "Invalid HMAC signature in webhook (tried " +
          credentials.hmacKeys.length +
          " key(s))",
      );
      console.error("Received:", hmacSignature);
      if (signatureResult.lastCalculated) {
        console.error(
          "Last key - documented:",
          signatureResult.lastCalculated.documented.base64,
        );
        console.error(
          "Last key - webhook order:",
          signatureResult.lastCalculated.webhookOrder.base64,
        );
      }
      console.error("Full payload:", JSON.stringify(payload, null, 2));
      return res.status(403).send("Invalid HMAC signature");
    }

    console.log("HMAC signature validated successfully");

    const eventType = additionalData?.eventType;
    const paymentId = merchantReference || checkoutReference;

    console.log(
      `STRAUMUR WEBHOOK RECEIVED - Event: ${eventType}, Payment ID: ${paymentId}, Success: ${success}`,
    );

    if (!paymentId) {
      console.error("No payment reference found in webhook payload");
      return res.status(400).send("No payment reference found");
    }

    // Get payment request
    const paymentRequest = await getPaymentRequest(
      paymentId,
      credentials.apiKey,
    );
    if (!paymentRequest) {
      console.error(`Payment request not found for ID: ${paymentId}`);
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
          await completePaymentRequest(
            paymentId,
            credentials.apiKey,
            credentials.gatewaySecret,
          );
        }
        break;

      case "Capture":
        if (success === "true") {
          // Complete the payment request
          await completePaymentRequest(
            paymentId,
            credentials.apiKey,
            credentials.gatewaySecret,
          );
        } else {
          console.error(
            `Capture failed for payment: ${paymentId}, Reason: ${reason}`,
          );
          // Handle failed capture
        }
        break;

      default:
        console.warn(
          `Unknown event type: ${eventType} for payment: ${paymentId}`,
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

app.post("/:sellerId/payment/refund", async (req, res) => {
  try {
    const sellerContext = requireSellerCredentials(req, res);
    if (!sellerContext) return;
    const { credentials } = sellerContext;

    const payload = req.body;

    if (payload.type !== "payment.refund") {
      return res.status(400).send("unsupported type");
    }

    const signature = crypto
      .createHmac("sha256", credentials.gatewaySecret)
      .update(req.rawBody)
      .digest("hex");

    const requestSignature = req.headers["x-vivenu-signature"];
    if (typeof requestSignature !== "string") {
      return res.status(400).send("missing signature");
    }
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

    const transactionDetails = await getTransactionById(
      transactionId,
      credentials.apiKey,
    );

    const checkoutId = transactionDetails.checkoutId;

    const checkoutDetails = await getCheckoutById(
      checkoutId,
      credentials.apiKey,
    );

    const paymentRequestId =
      checkoutDetails.docs[0] && checkoutDetails.docs[0].paymentRequestId;

    const checkoutStatus = await getStraumurCheckoutStatus(
      paymentRequestId,
      credentials.straumurApiKey,
    );

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
      refundReason,
      credentials.straumurApiKey,
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
});
