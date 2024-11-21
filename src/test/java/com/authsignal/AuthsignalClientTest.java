package com.authsignal;

import org.junit.Test;

import com.authsignal.exception.AuthsignalException;
import com.authsignal.model.*;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.HashMap;
import java.util.Properties;
import java.util.UUID;

public class AuthsignalClientTest {
    private final String baseURL;
    private AuthsignalClient client;

    public AuthsignalClientTest() throws FileNotFoundException, IOException {
        Properties localProperties = new Properties();
        localProperties.load(new FileInputStream(System.getProperty("user.dir") + "/local.properties"));

        baseURL = localProperties.getProperty("test.baseURL");

        String secret = localProperties.getProperty("test.secret");

        client = new AuthsignalClient(secret, baseURL);
    }

    @Test
    public void testInvalidApiSecretKey() {
        AuthsignalClient invalidClient = new AuthsignalClient("invalid_secret", baseURL);

        String userId = UUID.randomUUID().toString();

        UserRequest userRequest = new UserRequest();
        userRequest.userId = userId;

        try {
            invalidClient.getUser(userRequest).get();

            fail("should throw ExecutionException");
        } catch (ExecutionException e) {
            assertTrue("cause should be an AuthsignalException", e.getCause() instanceof AuthsignalException);

            AuthsignalException exception = (AuthsignalException) e.getCause();
            String errorCode = exception.getErrorCode();
            String errorDescription = exception.getErrorDescription();

            assertTrue("error code should be unauthorized", errorCode.equals("unauthorized"));

            String expectedDescription = "The request is unauthorized. Check that your API key and region base URL are correctly configured.";
            assertTrue("error code should be unauthorized", errorDescription.equals(expectedDescription));
        } catch (Exception e) {
            fail("should not throw any other exception");
        }
    }

    @Test
    public void testUser() {
        String userId = UUID.randomUUID().toString();

        EnrollVerifiedAuthenticatorRequest enrollRequest = new EnrollVerifiedAuthenticatorRequest();
        enrollRequest.userId = userId;
        enrollRequest.verificationMethod = VerificationMethodType.SMS;
        enrollRequest.phoneNumber = "+6427000000";

        try {
            EnrollVerifiedAuthenticatorResponse enrollResponse = client.enrollVerifiedAuthenticator(enrollRequest)
                    .get();

            assertNotNull("enrollResponse should exist", enrollResponse);

            UserRequest userRequest = new UserRequest();
            userRequest.userId = userId;

            UserResponse userResponse = client.getUser(userRequest).get();

            assertNotNull("userResponse should exist", userResponse);
            assertTrue("user should be enrolled", userResponse.isEnrolled);
            assertNull("email should be null", userResponse.email);

            UpdateUserRequest updateUserRequest = new UpdateUserRequest();
            updateUserRequest.email = "test@example.com";
            updateUserRequest.phoneNumber = "+6427123456";
            updateUserRequest.username = "Test User";
            updateUserRequest.displayName = "test@example.com";
            updateUserRequest.custom = new HashMap<>();
            updateUserRequest.custom.put("foo", "bar");

            UpdateUserResponse updateUserResponse = client.updateUser(updateUserRequest).get();

            assertNotNull("updateUserResponse should exist", updateUserResponse);
            assertEquals("email should match", updateUserRequest.email, updateUserResponse.email);
            assertEquals("phoneNumber should match", updateUserRequest.phoneNumber, updateUserResponse.phoneNumber);
            assertEquals("username should match", updateUserRequest.username, updateUserResponse.username);
            assertEquals("displayName should match", updateUserRequest.displayName, updateUserResponse.displayName);
            assertEquals("custom data should match", "bar", updateUserResponse.custom.get("foo"));

            client.deleteUser(userRequest).get();

            UserResponse deletedUserResponse = client.getUser(userRequest).get();

            assertFalse("user should not be enrolled", deletedUserResponse.isEnrolled);
        } catch (Exception e) {
            System.out.println(e.getMessage());

            fail("should not throw any exception");
        }
    }

    @Test
    public void testAuthenticator() {
        String userId = UUID.randomUUID().toString();

        EnrollVerifiedAuthenticatorRequest enrollRequest = new EnrollVerifiedAuthenticatorRequest();
        enrollRequest.userId = userId;
        enrollRequest.verificationMethod = VerificationMethodType.SMS;
        enrollRequest.phoneNumber = "+6427000000";

        try {
            EnrollVerifiedAuthenticatorResponse enrollResponse = client.enrollVerifiedAuthenticator(enrollRequest)
                    .get();

            assertNotNull("enrollResponse should exist", enrollResponse);

            UserRequest userRequest = new UserRequest();
            userRequest.userId = userId;

            UserAuthenticator[] authenticators = client.getAuthenticators(userRequest).get();

            assertNotNull("authenticators should exist", authenticators);
            assertTrue("authenticators should not be empty", authenticators.length > 0);

            UserAuthenticator authenticator = authenticators[0];

            assertEquals("verification method should be SMS", VerificationMethodType.SMS,
                    authenticator.verificationMethod);

            DeleteAuthenticatorRequest deleteAuthenticatorRequest = new DeleteAuthenticatorRequest();
            deleteAuthenticatorRequest.userId = userId;
            deleteAuthenticatorRequest.userAuthenticatorId = authenticator.userAuthenticatorId;

            client.deleteAuthenticator(deleteAuthenticatorRequest).get();

            UserAuthenticator[] emptyAuthenticators = client.getAuthenticators(userRequest).get();

            assertTrue("authenticators should be empty", emptyAuthenticators.length == 0);
        } catch (Exception e) {
            System.out.println(e.getMessage());

            fail("should not throw any exception");
        }
    }

    @Test
    public void testAction() {
        String userId = UUID.randomUUID().toString();

        EnrollVerifiedAuthenticatorRequest enrollRequest = new EnrollVerifiedAuthenticatorRequest();
        enrollRequest.userId = userId;
        enrollRequest.verificationMethod = VerificationMethodType.SMS;
        enrollRequest.phoneNumber = "+6427000000";

        try {
            EnrollVerifiedAuthenticatorResponse enrollResponse = client.enrollVerifiedAuthenticator(enrollRequest)
                    .get();

            assertNotNull("enrollResponse should exist", enrollResponse);

            TrackRequest trackRequest = new TrackRequest();
            trackRequest.userId = userId;
            trackRequest.action = "signIn";

            TrackResponse trackResponse = client.track(trackRequest).get();

            assertNotNull("trackResponse should exist", trackResponse);
            assertEquals("state should be CHALLENGE_REQUIRED", UserActionState.CHALLENGE_REQUIRED, trackResponse.state);

            String idempotencyKey = trackResponse.idempotencyKey;

            ValidateChallengeRequest validateRequest = new ValidateChallengeRequest();
            validateRequest.token = trackResponse.token;

            ValidateChallengeResponse validateResponse = client.validateChallenge(validateRequest).get();

            assertNotNull("validateResponse should exist", validateResponse);
            assertEquals("state should be CHALLENGE_REQUIRED", UserActionState.CHALLENGE_REQUIRED,
                    validateResponse.state);
            assertEquals("idempotency key should match", idempotencyKey, validateResponse.idempotencyKey);
            assertEquals("user should match", userId, validateResponse.userId);
            assertEquals("action should match", trackRequest.action, validateResponse.action);

            UpdateActionStateRequest updateActionRequest = new UpdateActionStateRequest();
            updateActionRequest.userId = userId;
            updateActionRequest.action = trackRequest.action;
            updateActionRequest.idempotencyKey = idempotencyKey;
            updateActionRequest.state = UserActionState.REVIEW_REQUIRED;

            ActionResponse updateActionResponse = client.updateActionState(updateActionRequest).get();

            assertNotNull("updateActionResponse should exist", updateActionResponse);
            assertEquals("state should be REVIEW_REQUIRED", UserActionState.REVIEW_REQUIRED,
                    updateActionResponse.state);
        } catch (Exception e) {
            System.out.println(e.getMessage());

            fail("should not throw any exception");
        }
    }

    @Test
    public void testPasskeyAuthenticator() {
        String userId = "b60429a1-6288-43dc-80c0-6a3e73dd51b9";

        UserRequest userRequest = new UserRequest();
        userRequest.userId = userId;

        try {
            UserAuthenticator[] authenticators = client.getAuthenticators(userRequest).get();

            System.out.println(authenticators.length);

            assertNotNull("authenticators should exist", authenticators);
            assertTrue("authenticators should not be empty", authenticators.length > 0);

            for (UserAuthenticator authenticator : authenticators) {
                if (authenticator.verificationMethod == VerificationMethodType.PASSKEY) {
                    String name = authenticator.webauthnCredential.aaguidMapping.name;

                    assertTrue("should be a known passkey backend",
                            name.equals("Google Password Manager") || name.equals("iCloud Keychain"));
                }
            }

        } catch (Exception e) {
            System.out.println(e.getMessage());

            fail("should not throw any exception");
        }
    }
}
