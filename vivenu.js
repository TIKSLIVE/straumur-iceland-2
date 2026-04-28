import { nanoid } from "nanoid";
import fetch from "node-fetch";

const VIVENU_URL = process.env.VIVENU_URL || "https://vivenu.com";

function getAuthHeaders(apiKey) {
  return {
    "Content-Type": "application/json",
    Accept: "application/json",
    Authorization: `Bearer ${apiKey}`,
  };
}

export const getPaymentRequest = async (paymentId, apiKey) => {
  try {
    const response = await fetch(
      `${VIVENU_URL}/api/payments/requests/${paymentId}`,
      {
        method: "GET",
        headers: getAuthHeaders(apiKey),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch payment request: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching payment request:", error.message);
    throw error;
  }
};

export const getTransactionById = async (transactionId, apiKey) => {
  try {
    const response = await fetch(
      `${VIVENU_URL}/api/transactions/${transactionId}`,
      {
        method: "GET",
        headers: getAuthHeaders(apiKey),
      }
    );

    if (!response.ok) {
      throw new Error(
        `Failed to fetch transaction request: ${response.status}`
      );
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching transaction request:", error.message);
    throw error;
  }
};

export const getCheckoutById = async (checkoutId, apiKey) => {
  try {
    const response = await fetch(
      `${VIVENU_URL}/api/payments?checkoutId=${checkoutId}`,
      {
        method: "GET",
        headers: getAuthHeaders(apiKey),
      }
    );

    if (!response.ok) {
      throw new Error(
        `Failed to fetch transaction request: ${response.status}`
      );
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching transaction request:", error.message);
    throw error;
  }
};

export const completePaymentRequest = async (
  paymentId,
  apiKey,
  gatewaySecret
) => {
  try {
    const response = await fetch(
      `${VIVENU_URL}/api/payments/requests/${paymentId}/confirm`,
      {
        method: "POST",
        headers: getAuthHeaders(apiKey),
        body: JSON.stringify({
          gatewaySecret,
          reference: nanoid(),
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to complete payment request: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("Error completing payment request:", error.message);
    throw error;
  }
};
