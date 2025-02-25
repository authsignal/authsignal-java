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
        String payload = "{"
            + "\"version\": 1,"
            + "\"id\": \"256759e3-d3b4-48f1-ad60-428300ab02cd\","
            + "\"source\": \"https://authsignal.com\","
            + "\"time\": \"2025-02-25T02:13:36.379Z\","
            + "\"tenantId\": \"7752d28e-e627-4b1b-bb81-b45d68d617bc\","
            + "\"type\": \"email.created\","
            + "\"data\": {"
            + "\"to\": \"steven@authsignal.com\","
            + "\"code\": \"696687\","
            + "\"userId\": \"steven\","
            + "\"actionCode\": \"sign-in\","
            + "\"idempotencyKey\": \"37d5c303-4132-4c59-8ee7-669e6943e3fb\","
            + "\"ipAddress\": \"95.31.18.119\","
            + "\"verificationMethod\": \"EMAIL_OTP\""
            + "}"
            + "}";

        // Ignore tolerance window
        int tolerance = -1;

        String signature = "t=1740449616,v2=kfKPJZkaxXRSCUdX0/OCNpfBdvRpK1U3Hd7ae8lREJU";

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
            + "\"version\": 1,"
            + "\"id\": \"256759e3-d3b4-48f1-ad60-428300ab02cd\","
            + "\"source\": \"https://authsignal.com\","
            + "\"time\": \"2025-02-25T02:13:36.379Z\","
            + "\"tenantId\": \"7752d28e-e627-4b1b-bb81-b45d68d617bc\","
            + "\"type\": \"email.created\","
            + "\"data\": {"
            + "\"to\": \"steven@authsignal.com\","
            + "\"code\": \"696687\","
            + "\"userId\": \"steven\","
            + "\"actionCode\": \"sign-in\","
            + "\"idempotencyKey\": \"37d5c303-4132-4c59-8ee7-669e6943e3fb\","
            + "\"ipAddress\": \"95.31.18.119\","
            + "\"verificationMethod\": \"EMAIL_OTP\""
            + "}"
            + "}";

        // Ignore tolerance window
        int tolerance = -1;

        String signature = "t=1740449616,v2=kfKPJZkaxXRSCUdX0/OCNpfBdvRpK1U3Hd7ae8lREJU";

        try {
            Object event = client.webhook.constructEvent(payload, signature, tolerance);
            assertNotNull(event);
        } catch (InvalidSignatureException ex) {
            fail("Expected a valid event to be constructed");
        }
    }
}
