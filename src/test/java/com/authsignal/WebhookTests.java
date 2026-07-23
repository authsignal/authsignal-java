package com.authsignal;

import org.junit.Test;
import static org.junit.Assert.*;

import com.authsignal.Webhook.InvalidSignatureException;
import com.authsignal.model.WebhookEvent;
import com.authsignal.model.WebhookEventBatch;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class WebhookTests {
    private static final String API_SECRET_KEY = "test-secret-key";
    private final Webhook webhook;

    public WebhookTests() {
        webhook = new Webhook(API_SECRET_KEY);
    }

    private String createSignature(String payload) {
        try {
            long timestamp = System.currentTimeMillis() / 1000;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(API_SECRET_KEY.getBytes(), "HmacSHA256"));
            byte[] hmacBytes = mac.doFinal((timestamp + "." + payload).getBytes());
            String signature = Base64.getEncoder().encodeToString(hmacBytes).replace("=", "");
            return "t=" + timestamp + ",v2=" + signature;
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute test signature", e);
        }
    }

    @Test
    public void testInvalidSignatureFormat() {
        String payload = "{}";
        String signature = "123";

        try {
            webhook.constructEvent(payload, signature);
            fail("Expected an AuthsignalException to be thrown");
        } catch (InvalidSignatureException ex) {
            assertEquals("Signature format is invalid.", ex.getMessage());
        }
    }

    @Test
    public void testTimestampToleranceError() {
        String payload = "{}";
        String signature = "t=1630000000,v2=invalid_signature";

        try {
            webhook.constructEvent(payload, signature);
            fail("Expected an AuthsignalException to be thrown");
        } catch (InvalidSignatureException ex) {
            assertEquals("Timestamp is outside the tolerance zone.", ex.getMessage());
        }
    }

    @Test
    public void testInvalidComputedSignature() {
        String payload = "{}";
        long timestamp = System.currentTimeMillis() / 1000;
        String signature = "t=" + timestamp + ",v2=invalid_signature";

        try {
            webhook.constructEvent(payload, signature);
            fail("Expected an AuthsignalException to be thrown");
        } catch (InvalidSignatureException ex) {
            assertEquals("Signature mismatch.", ex.getMessage());
        }
    }

    @Test
    public void testValidSignature() {
        // Payload should omit whitespace
        String payload = "{"
                + "\"version\":1,"
                + "\"id\":\"bc1598bc-e5d6-4c69-9afb-1a6fe3469d6e\","
                + "\"source\":\"https://authsignal.com\","
                + "\"time\":\"2025-02-20T01:51:56.070Z\","
                + "\"tenantId\":\"7752d28e-e627-4b1b-bb81-b45d68d617bc\","
                + "\"type\":\"email.created\","
                + "\"data\":{"
                + "\"to\":\"chris@authsignal.com\","
                + "\"code\":\"157743\","
                + "\"userId\":\"b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0\","
                + "\"actionCode\":\"accountRecovery\","
                + "\"idempotencyKey\":\"ba8c1a7c-775d-4dff-9abe-be798b7b8bb9\","
                + "\"verificationMethod\":\"EMAIL_OTP\""
                + "}"
                + "}";

        try {
            WebhookEvent event = webhook.constructEvent(payload, createSignature(payload));

            assertNotNull(event);

            assertEquals(1, event.version);

            assertEquals("accountRecovery", event.data.get("actionCode"));
        } catch (InvalidSignatureException ex) {
            fail("Expected a valid event to be constructed");
        }
    }

    @Test
    public void testValidSignatureWhenTwoApiKeysActive() {
        String payload = "{"
                + "\"version\":1,"
                + "\"id\":\"af7be03c-ea8f-4739-b18e-8b48fcbe4e38\","
                + "\"source\":\"https://authsignal.com\","
                + "\"time\":\"2025-02-20T01:47:17.248Z\","
                + "\"tenantId\":\"7752d28e-e627-4b1b-bb81-b45d68d617bc\","
                + "\"type\":\"email.created\","
                + "\"data\":{"
                + "\"to\":\"chris@authsignal.com\","
                + "\"code\":\"718190\","
                + "\"userId\":\"b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0\","
                + "\"actionCode\":\"accountRecovery\","
                + "\"idempotencyKey\":\"68d68190-fac9-4e91-b277-c63d31d3c6b1\","
                + "\"verificationMethod\":\"EMAIL_OTP\""
                + "}"
                + "}";

        try {
            String signature = createSignature(payload) + ",v2=invalid_signature";
            WebhookEvent event = webhook.constructEvent(payload, signature);

            assertNotNull(event);
        } catch (InvalidSignatureException ex) {
            fail("Expected a valid event to be constructed");
        }
    }

    @Test
    public void testEventWithCustomVariables() {
        String payload = "{"
                + "\"version\":1,"
                + "\"id\":\"bc1598bc-e5d6-4c69-9afb-1a6fe3469d6e\","
                + "\"source\":\"https://authsignal.com\","
                + "\"time\":\"2025-02-20T01:51:56.070Z\","
                + "\"tenantId\":\"7752d28e-e627-4b1b-bb81-b45d68d617bc\","
                + "\"type\":\"sms.created\","
                + "\"data\":{"
                + "\"actionCode\":\"smsVerify\","
                + "\"customVariables\":{"
                + "\"action_journeyType\":\"ForgotChangePassword\","
                + "\"retryCount\":2,"
                + "\"isRecovery\":true,"
                + "\"channels\":[\"sms\",\"email\"]"
                + "}"
                + "}"
                + "}";

        try {
            WebhookEvent event = webhook.constructEvent(payload, createSignature(payload));

            assertTrue(event.data.get("customVariables") instanceof Map);
            Map<?, ?> customVariables = (Map<?, ?>) event.data.get("customVariables");
            assertEquals("ForgotChangePassword", customVariables.get("action_journeyType"));
            assertEquals(2.0, customVariables.get("retryCount"));
            assertEquals(true, customVariables.get("isRecovery"));
            assertTrue(customVariables.get("channels") instanceof List);
            assertEquals("sms", ((List<?>) customVariables.get("channels")).get(0));
        } catch (InvalidSignatureException ex) {
            fail("Expected an event with custom variables to be constructed");
        }
    }

    @Test
    public void testLogEventBatch() {
        String payload = "{\"records\":[{"
                + "\"version\":1,"
                + "\"id\":\"bc1598bc-e5d6-4c69-9afb-1a6fe3469d6e\","
                + "\"source\":\"https://authsignal.com\","
                + "\"time\":\"2025-02-20T01:51:56.070Z\","
                + "\"tenantId\":\"7752d28e-e627-4b1b-bb81-b45d68d617bc\","
                + "\"type\":\"action.log_created\","
                + "\"record\":{"
                + "\"userId\":\"b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0\","
                + "\"customVariables\":{\"journeyType\":\"accountRecovery\"}"
                + "}"
                + "}]}";

        try {
            WebhookEventBatch batch = webhook.constructLogEventBatch(payload, createSignature(payload));

            assertEquals(1, batch.records.size());
            assertTrue(batch.records.get(0).record.get("customVariables") instanceof Map);
        } catch (InvalidSignatureException ex) {
            fail("Expected a log event batch to be constructed");
        }
    }

    @Test
    public void testLogEventBatchPassedToConstructEvent() {
        String payload = "{\"records\":[]}";

        try {
            webhook.constructEvent(payload, createSignature(payload));
            fail("Expected an InvalidPayloadException to be thrown");
        } catch (Webhook.InvalidPayloadException ex) {
            assertTrue(ex.getMessage().contains("constructLogEventBatch"));
        } catch (InvalidSignatureException ex) {
            fail("Expected a valid signature");
        }
    }

    @Test
    public void testInvalidPayload() {
        String payload = "not-json";

        try {
            webhook.constructEvent(payload, createSignature(payload));
            fail("Expected an InvalidPayloadException to be thrown");
        } catch (Webhook.InvalidPayloadException ex) {
            assertEquals("Payload format is invalid.", ex.getMessage());
        } catch (InvalidSignatureException ex) {
            fail("Expected a valid signature");
        }
    }
}
