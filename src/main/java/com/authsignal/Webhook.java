package com.authsignal;

import com.authsignal.model.WebhookEvent;
import com.authsignal.model.WebhookEventBatch;
import com.authsignal.model.WebhookLogEvent;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

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
        verifySignature(payload, signature, tolerance);

        JsonObject parsedPayload = parsePayload(payload);

        if (parsedPayload.has("records")) {
            throw new InvalidPayloadException(
                    "Payload is a batch of log events. Use constructLogEventBatch instead.");
        }

        WebhookEvent event = deserializePayload(parsedPayload, WebhookEvent.class);
        validateEvent(event);

        return event;
    }

    public WebhookEvent constructEvent(String payload, String signature) throws InvalidSignatureException {
        return constructEvent(payload, signature, DEFAULT_TOLERANCE);
    }

    public WebhookEventBatch constructLogEventBatch(String payload, String signature, int tolerance)
            throws InvalidSignatureException {
        verifySignature(payload, signature, tolerance);

        JsonObject parsedPayload = parsePayload(payload);
        WebhookEventBatch batch = deserializePayload(parsedPayload, WebhookEventBatch.class);

        if (batch.records == null) {
            throw new InvalidPayloadException("Payload format is invalid. Expected a 'records' array.");
        }

        for (WebhookLogEvent event : batch.records) {
            validateLogEvent(event);
        }

        return batch;
    }

    public WebhookEventBatch constructLogEventBatch(String payload, String signature)
            throws InvalidSignatureException {
        return constructLogEventBatch(payload, signature, DEFAULT_TOLERANCE);
    }

    private void verifySignature(String payload, String signature, int tolerance)
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
    }

    private JsonObject parsePayload(String payload) {
        try {
            return JsonParser.parseString(payload).getAsJsonObject();
        } catch (Exception exception) {
            throw new InvalidPayloadException("Payload format is invalid.", exception);
        }
    }

    private <T> T deserializePayload(JsonObject payload, Class<T> payloadClass) {
        try {
            return new Gson().fromJson(payload, payloadClass);
        } catch (Exception exception) {
            throw new InvalidPayloadException("Payload format is invalid.", exception);
        }
    }

    private void validateEvent(WebhookEvent event) {
        validateEnvelope(event.version, event.type, event.id, event.source, event.time, event.tenantId);

        if (event.data == null) {
            throw new InvalidPayloadException("Payload is missing required field 'data'.");
        }
    }

    private void validateLogEvent(WebhookLogEvent event) {
        validateEnvelope(event.version, event.type, event.id, event.source, event.time, event.tenantId);

        if (event.record == null) {
            throw new InvalidPayloadException("Payload is missing required field 'record'.");
        }
    }

    private void validateEnvelope(
            int version, String type, String id, String source, String time, String tenantId) {
        if (version <= 0) {
            throw new InvalidPayloadException("Payload is missing required field 'version'.");
        }

        requireField(type, "type");
        requireField(id, "id");
        requireField(source, "source");
        requireField(time, "time");
        requireField(tenantId, "tenantId");
    }

    private void requireField(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new InvalidPayloadException("Payload is missing required field '" + name + "'.");
        }
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

    public static class InvalidPayloadException extends RuntimeException {
        public InvalidPayloadException(String message) {
            super(message);
        }

        public InvalidPayloadException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
