import { nanoid } from "nanoid";
import axios from "axios";

const VIVENU_URL = process.env.VIVENU_URL || "https://vivenu.com";
const API_KEY = process.env.API_KEY;
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;

const vivenuHeaders = {
  "Content-Type": "application/json",
  Accept: "application/json",
  Authorization: `Bearer ${API_KEY}`,
};

export const getPaymentRequest = async (paymentId) => {
  try {
    const response = await axios.get(
      `${VIVENU_URL}/api/payments/requests/${paymentId}`,
      { headers: vivenuHeaders }
    );
    return response.data;
  } catch (error) {
    console.error("Error fetching payment request:", error.message);
    throw error;
  }
};

export const getTransactionById = async (transactionId) => {
  try {
    const response = await axios.get(
      `${VIVENU_URL}/api/transactions/${transactionId}`,
      { headers: vivenuHeaders }
    );
    return response.data;
  } catch (error) {
    console.error("Error fetching transaction request:", error.message);
    throw error;
  }
};

export const getCheckoutById = async (checkoutId) => {
  try {
    const response = await axios.get(
      `${VIVENU_URL}/api/payments?checkoutId=${checkoutId}`,
      { headers: vivenuHeaders }
    );
    return response.data;
  } catch (error) {
    console.error("Error fetching transaction request:", error.message);
    throw error;
  }
};

export const getCheckoutDetails = async (checkoutId, secret) => {
  try {
    const params = secret ? { secret } : {};
    const response = await axios.get(
      `${VIVENU_URL}/api/checkout/${checkoutId}`,
      { headers: vivenuHeaders, params }
    );
    return response.data;
  } catch (error) {
    console.error("Error fetching checkout details:", error.message);
    throw error;
  }
};

export const completePaymentRequest = async (paymentId) => {
  try {
    const response = await axios.post(
      `${VIVENU_URL}/api/payments/requests/${paymentId}/confirm`,
      {
        gatewaySecret: GATEWAY_SECRET,
        reference: nanoid(16),
      },
      { headers: vivenuHeaders }
    );
    return response.data;
  } catch (error) {
    console.error("Error completing payment request:", error.message);
    throw error;
  }
};
