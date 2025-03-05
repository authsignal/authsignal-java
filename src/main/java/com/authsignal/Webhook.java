package com.authsignal;

import com.authsignal.model.WebhookEvent;
import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Webhook {
    private static final int DEFAULT_TOLERANCE = 5;
    private static final String VERSION = "v2";
    private final String apiSecretKey;

    public Webhook(String apiSecretKey) {
        this.apiSecretKey = apiSecretKey;
    }

    public WebhookEvent constructEvent(String payload, String signature, int tolerance)
            throws InvalidSignatureException {
        SignatureHeaderData parsedSignature = parseSignature(signature);

        long secondsSinceEpoch = System.currentTimeMillis() / 1000;

        if (tolerance > 0 && parsedSignature.timestamp < secondsSinceEpoch - tolerance * 60) {
            throw new InvalidSignatureException("Timestamp is outside the tolerance zone.");
        }

        String hmacContent = parsedSignature.timestamp + "." + payload;

        String computedSignature = computeHmac(hmacContent, apiSecretKey);

        boolean match = parsedSignature.signatures.stream().anyMatch(sig -> sig.equals(computedSignature));

        if (!match) {
            throw new InvalidSignatureException("Signature mismatch.");
        }

        return new Gson().fromJson(payload, WebhookEvent.class);
    }

    public WebhookEvent constructEvent(String payload, String signature) throws InvalidSignatureException {
        return constructEvent(payload, signature, DEFAULT_TOLERANCE);
    }

    private SignatureHeaderData parseSignature(String value) throws InvalidSignatureException {
        try {
            long timestamp = getTimestamp(value);
            List<String> signatures = getSignatures(value);

            if (timestamp == -1 || signatures.isEmpty()) {
                throw new RuntimeException();
            }

            return new SignatureHeaderData(signatures, timestamp);
        } catch (Exception e) {
            throw new InvalidSignatureException("Signature format is invalid.");
        }
    }

    private static long getTimestamp(String header) {
        String[] items = header.split(",", -1);

        for (String item : items) {
            String[] itemParts = item.split("=", 2);
            if (itemParts[0].equals("t")) {
                return Long.parseLong(itemParts[1]);
            }
        }

        return -1;
    }

    private static List<String> getSignatures(String header) {
        List<String> signatures = new ArrayList<String>();
        String[] items = header.split(",", -1);

        for (String item : items) {
            String[] itemParts = item.split("=", 2);
            if (itemParts[0].equals(VERSION)) {
                signatures.add(itemParts[1]);
            }
        }

        return signatures;
    }

    private String computeHmac(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(hmacBytes).replace("=", "");
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute HMAC", e);
        }
    }

    private static class SignatureHeaderData {
        public List<String> signatures;
        public long timestamp;

        public SignatureHeaderData(List<String> signatures, long timestamp) {
            this.signatures = signatures;
            this.timestamp = timestamp;
        }
    }

    public static class InvalidSignatureException extends Exception {
        public InvalidSignatureException(String message) {
            super(message);
        }
    }
}
