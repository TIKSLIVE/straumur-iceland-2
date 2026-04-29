import * as crypto from "crypto";
import axios from "axios";

// --- Straumur API config ---

const STRAUMUR_BASE_URL = "https://greidslugatt.straumur.is/api/v1";
export const STRAUMUR_PATHS = {
  hostedCheckout: `${STRAUMUR_BASE_URL}/hostedcheckout`,
  checkoutStatus: `${STRAUMUR_BASE_URL}/hostedcheckout/status`,
  refund: `${STRAUMUR_BASE_URL}/modification/refund`,
};

// --- Validation ---

const ID_PATTERN = /^[a-zA-Z0-9_:.\-]{1,200}$/;
export function isValidId(id) {
  return typeof id === "string" && ID_PATTERN.test(id);
}


// --- Security ---

export function timingSafeStringEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// --- Reference helpers ---

export function buildCompositeRef(sellerId, eventId, paymentRequestId) {
  return `${sellerId}:${eventId}:${paymentRequestId}`;
}

export function parseCompositeRef(ref) {
  const parts = ref.split(":");
  if (parts.length === 3) {
    return { sellerId: parts[0], eventId: parts[1], paymentRequestId: parts[2] };
  }
  return { sellerId: null, eventId: null, paymentRequestId: ref };
}

// --- Straumur HMAC ---

// Hex key → bytes (odd-length hex padded with "0" to match Straumur's reference implementation)
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

// Two field orderings are tried: the documented C# order and the actual webhook JSON order.
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

export function calculateStraumurHMAC(webhookSecretHex, payload) {
  const binaryKey = convertHexToByteArray(webhookSecretHex);
  const results = {};

  for (const [name, order] of Object.entries(SIGNATURE_FIELD_ORDERS)) {
    const signaturePayload = buildSignaturePayload(payload, order);
    const binaryPayload = Buffer.from(signaturePayload, "utf8");
    results[name] = {
      base64: crypto.createHmac("sha256", binaryKey).update(binaryPayload).digest("base64"),
      hex: crypto.createHmac("sha256", binaryKey).update(binaryPayload).digest("hex"),
      payloadString: signaturePayload,
    };
  }

  if (process.env.NODE_ENV !== "production") {
    console.log("=== DEBUG: PAYLOAD CONSTRUCTION ===");
    console.log("Documented order payload:", results.documented.payloadString);
    console.log("Webhook order payload:  ", results.webhookOrder.payloadString);
    console.log("==================================");
  }

  return results;
}

export function validateStraumurWebhookSignature(payload, hmacSignature, hmacKeys) {
  let lastCalculated = null;

  for (let i = 0; i < hmacKeys.length; i++) {
    const calculated = calculateStraumurHMAC(hmacKeys[i], payload);
    lastCalculated = calculated;

    const matchDocumented = timingSafeStringEqual(hmacSignature, calculated.documented.base64);
    const matchWebhookOrder = timingSafeStringEqual(hmacSignature, calculated.webhookOrder.base64);

    if (matchDocumented || matchWebhookOrder) {
      return {
        validated: true,
        matchedWebhookOrderOnly: matchWebhookOrder && !matchDocumented,
        keyIndex: i,
      };
    }
  }

  return { validated: false, lastCalculated };
}

// --- Straumur API client ---

function getStraumurHeaders() {
  return {
    "X-API-key": process.env.STRAUMUR_API_KEY,
    "Content-Type": "application/json",
    "Cache-Control": "no-cache",
  };
}

function logAxiosError(prefix, error) {
  console.error(prefix, error.response ? error.response.data : error.message);
}

export async function initializeTransaction(amount, paymentId, callbackUrl, currency) {
  const fields = {
    amount: Math.round(amount),
    currency: currency || process.env.CURRENCY || "ISK",
    returnUrl: callbackUrl,
    reference: paymentId,
    terminalIdentifier: process.env.STRAUMUR_TERMINAL_ID,
  };

  try {
    const response = await axios.post(STRAUMUR_PATHS.hostedCheckout, fields, {
      headers: getStraumurHeaders(),
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

export async function getStraumurCheckoutStatus(checkoutReference) {
  try {
    const response = await axios.get(
      `${STRAUMUR_PATHS.checkoutStatus}/${checkoutReference}`,
      { headers: getStraumurHeaders() }
    );
    return response.data;
  } catch (error) {
    logAxiosError("Error getting Straumur checkout status:", error);
    throw error;
  }
}

const VALID_REFUND_REASONS = ["OTHER", "RETURN", "DUPLICATE", "FRAUD", "CUSTOMER REQUEST"];

export async function createStraumurRefund(
  merchantReference,
  payfacReference,
  amount,
  currency = "ISK",
  refundReason = null
) {
  const data = {
    reference: merchantReference,
    payfacReference,
    amount,
    currency,
    ...(refundReason && VALID_REFUND_REASONS.includes(refundReason) && { refundReason }),
  };

  try {
    const response = await axios.post(STRAUMUR_PATHS.refund, data, {
      headers: getStraumurHeaders(),
    });
    console.log("Straumur refund created successfully:", response.data);
    return { success: true, data: response.data };
  } catch (error) {
    logAxiosError("Error creating Straumur refund:", error);
    return {
      success: false,
      error: error.response ? error.response.data : error.message,
    };
  }
}
