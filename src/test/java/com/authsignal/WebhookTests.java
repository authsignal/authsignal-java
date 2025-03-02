package com.authsignal;

import org.junit.Test;
import static org.junit.Assert.*;

import com.authsignal.Webhook.InvalidSignatureException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class WebhookTests {
    private final String baseURL;
    private AuthsignalClient client;

    public WebhookTests() throws FileNotFoundException, IOException {
        Properties localProperties = new Properties();
        localProperties.load(new FileInputStream(System.getProperty("user.dir") + "/local.properties"));

        baseURL = localProperties.getProperty("test.baseURL");

        String secret = localProperties.getProperty("test.secret");

        client = new AuthsignalClient(secret, baseURL);
    }

    @Test
    public void testInvalidSignatureFormat() {
        String payload = "{}";
        String signature = "123";

        try {
            client.webhook.constructEvent(payload, signature);
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
            client.webhook.constructEvent(payload, signature);
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
            client.webhook.constructEvent(payload, signature);
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

        // Ignore tolerance window
        int tolerance = -1;

        String signature = "t=1740016316,v2=NwFcIT68pK7g+m365Jj4euXj/ke3GSnkTpMPcRVi5q4";

        try {
            Object event = client.webhook.constructEvent(payload, signature, tolerance);
            assertNotNull(event);
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

        // Ignore tolerance window
        int tolerance = -1;

        String signature = "t=1740016037,v2=zI5rg1XJtKH8dXTX9VCSwy07qTPJliXkK9ppgNjmzqw,v2=KMg8mXXGO/SmNNmcszKXI4UaEVHLc21YNWthHfispQo";

        try {
            Object event = client.webhook.constructEvent(payload, signature, tolerance);
            assertNotNull(event);
        } catch (InvalidSignatureException ex) {
            fail("Expected a valid event to be constructed");
        }
    }
}
