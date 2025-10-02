package com.authsignal;

import org.junit.Test;
import static org.junit.Assert.*;

import com.authsignal.exception.AuthsignalException;
import com.authsignal.model.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.HashMap;
import java.util.Properties;
import java.util.UUID;

public class AuthsignalClientTests {
    private final String baseURL;
    private AuthsignalClient client;

    public AuthsignalClientTests() {
        baseURL = getProp("AUTHSIGNAL_URL");

        String secret = getProp("AUTHSIGNAL_SECRET");

        client = new AuthsignalClient(secret, baseURL);
    }

    private String getProp(String name) {
        String value = System.getenv(name);

        if (value == null) {
            try {
                Properties localProperties = new Properties();
                localProperties.load(new FileInputStream(System.getProperty("user.dir") + "/local.properties"));
                value = localProperties.getProperty(name);
            } catch (IOException e) {
                throw new RuntimeException("Failed to load properties file", e);
            }
        }

        return value;
    }

    @Test
    public void testInvalidApiSecretKey() {
        AuthsignalClient invalidClient = new AuthsignalClient("invalid_secret", baseURL);

        String userId = UUID.randomUUID().toString();

        GetUserRequest userRequest = new GetUserRequest();
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
        enrollRequest.attributes = new EnrollVerifiedAuthenticatorAttributes();
        enrollRequest.attributes.verificationMethod = VerificationMethodType.SMS;
        enrollRequest.attributes.phoneNumber = "+6427000000";

        try {
            EnrollVerifiedAuthenticatorResponse enrollResponse = client.enrollVerifiedAuthenticator(enrollRequest)
                    .get();

            assertNotNull("enrollResponse should exist", enrollResponse);

            GetUserRequest userRequest = new GetUserRequest();
            userRequest.userId = userId;

            GetUserResponse userResponse = client.getUser(userRequest).get();

            assertNotNull("userResponse should exist", userResponse);
            assertTrue("user should be enrolled", userResponse.isEnrolled);
            assertNull("email should be null", userResponse.email);

            UpdateUserRequest updateUserRequest = new UpdateUserRequest();
            updateUserRequest.userId = userId;
            updateUserRequest.attributes = new UserAttributes();
            updateUserRequest.attributes.email = "test@example.com";
            updateUserRequest.attributes.phoneNumber = "+6427123456";
            updateUserRequest.attributes.username = "Test User";
            updateUserRequest.attributes.displayName = "test@example.com";
            updateUserRequest.attributes.custom = new HashMap<>();
            updateUserRequest.attributes.custom.put("foo", "bar");
            updateUserRequest.attributes.custom.put("baz", 1);

            UserAttributes updatedAttributes = client.updateUser(updateUserRequest).get();

            assertNotNull("updatedUserAttributes should exist", updatedAttributes);
            assertEquals("email should match", updateUserRequest.attributes.email, updatedAttributes.email);
            assertEquals("phoneNumber should match", updateUserRequest.attributes.phoneNumber,
                    updatedAttributes.phoneNumber);
            assertEquals("username should match", updateUserRequest.attributes.username,
                    updatedAttributes.username);
            assertEquals("displayName should match", updateUserRequest.attributes.displayName,
                    updatedAttributes.displayName);
            assertEquals("custom data should match", "bar", updateUserRequest.attributes.custom.get("foo"));

            DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
            deleteUserRequest.userId = userId;

            client.deleteUser(deleteUserRequest).get();

            GetUserResponse deletedUserResponse = client.getUser(userRequest).get();

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
        enrollRequest.attributes = new EnrollVerifiedAuthenticatorAttributes();
        enrollRequest.attributes.verificationMethod = VerificationMethodType.SMS;
        enrollRequest.attributes.phoneNumber = "+6427000000";

        try {
            EnrollVerifiedAuthenticatorResponse enrollResponse = client.enrollVerifiedAuthenticator(enrollRequest)
                    .get();

            assertNotNull("enrollResponse should exist", enrollResponse);

            GetAuthenticatorsRequest authenticatorsRequest = new GetAuthenticatorsRequest();
            authenticatorsRequest.userId = userId;

            UserAuthenticator[] authenticators = client.getAuthenticators(authenticatorsRequest).get();

            assertNotNull("authenticators should exist", authenticators);
            assertTrue("authenticators should not be empty", authenticators.length > 0);

            UserAuthenticator authenticator = authenticators[0];

            assertEquals("verification method should be SMS", VerificationMethodType.SMS,
                    authenticator.verificationMethod);

            DeleteAuthenticatorRequest deleteAuthenticatorRequest = new DeleteAuthenticatorRequest();
            deleteAuthenticatorRequest.userId = userId;
            deleteAuthenticatorRequest.userAuthenticatorId = authenticator.userAuthenticatorId;

            client.deleteAuthenticator(deleteAuthenticatorRequest).get();

            UserAuthenticator[] emptyAuthenticators = client.getAuthenticators(authenticatorsRequest).get();

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
        enrollRequest.attributes = new EnrollVerifiedAuthenticatorAttributes();
        enrollRequest.attributes.verificationMethod = VerificationMethodType.SMS;
        enrollRequest.attributes.phoneNumber = "+6427000000";

        try {
            EnrollVerifiedAuthenticatorResponse enrollResponse = client.enrollVerifiedAuthenticator(enrollRequest)
                    .get();

            assertNotNull("enrollResponse should exist", enrollResponse);

            TrackRequest trackRequest = new TrackRequest();
            trackRequest.userId = userId;
            trackRequest.action = "signIn";
            trackRequest.attributes = new TrackAttributes();
            trackRequest.attributes.custom = new HashMap<>();
            trackRequest.attributes.custom.put("foo", "bar");
            trackRequest.attributes.custom.put("baz", 1);

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

            UpdateActionRequest updateActionRequest = new UpdateActionRequest();
            updateActionRequest.userId = userId;
            updateActionRequest.action = trackRequest.action;
            updateActionRequest.idempotencyKey = idempotencyKey;
            updateActionRequest.attributes = new ActionAttributes();
            updateActionRequest.attributes.state = UserActionState.REVIEW_REQUIRED;

            ActionAttributes updatedAttributes = client.updateAction(updateActionRequest).get();

            assertNotNull("updatedAttributes should exist", updatedAttributes);
            assertEquals("state should be REVIEW_REQUIRED", UserActionState.REVIEW_REQUIRED,
                    updatedAttributes.state);
        } catch (Exception e) {
            System.out.println(e.getMessage());

            fail("should not throw any exception");
        }
    }

    @Test
    public void testPasskeyAuthenticator() {
        String userId = "b60429a1-6288-43dc-80c0-6a3e73dd51b9";

        GetAuthenticatorsRequest authenticatorsRequest = new GetAuthenticatorsRequest();
        authenticatorsRequest.userId = userId;

        try {
            UserAuthenticator[] authenticators = client.getAuthenticators(authenticatorsRequest).get();

            System.out.println(authenticators.length);

            assertNotNull("authenticators should exist", authenticators);
            assertTrue("authenticators should not be empty", authenticators.length > 0);

            for (UserAuthenticator authenticator : authenticators) {
                if (authenticator.verificationMethod == VerificationMethodType.PASSKEY) {
                    String name = authenticator.webauthnCredential.aaguidMapping.name;

                    assertTrue("should be a known passkey backend",
                            name.equals("Google Password Manager") || name.equals("iCloud Keychain"));

                    assertTrue(authenticator.webauthnCredential.parsedUserAgent.browser.name.equals("Chrome"));
                }
            }

        } catch (Exception e) {
            System.out.println(e.getMessage());

            fail("should not throw any exception");
        }
    }

    @Test
    public void testQueryUsers() {
        String userId = UUID.randomUUID().toString();
        String testEmail = "test-" + UUID.randomUUID().toString() + "@example.com";

        try {
            // First create a user with a unique email
            UpdateUserRequest updateUserRequest = new UpdateUserRequest();
            updateUserRequest.userId = userId;
            updateUserRequest.attributes = new UserAttributes();
            updateUserRequest.attributes.email = testEmail;

            client.updateUser(updateUserRequest).get();

            // Query by email
            QueryUsersRequest queryRequest = new QueryUsersRequest();
            queryRequest.email = testEmail;

            QueryUsersResponse queryResponse = client.queryUsers(queryRequest).get();

            assertNotNull("queryResponse should exist", queryResponse);
            assertNotNull("users array should exist", queryResponse.users);
            assertTrue("users array should not be empty", queryResponse.users.length > 0);

            QueryUsersResponseUser user = queryResponse.users[0];
            assertEquals("userId should match", userId, user.userId);
            assertEquals("email should match", testEmail, user.email);

            // Test pagination with limit
            QueryUsersRequest limitRequest = new QueryUsersRequest();
            limitRequest.email = testEmail;
            limitRequest.limit = 1;

            QueryUsersResponse limitResponse = client.queryUsers(limitRequest).get();

            assertNotNull("limitResponse should exist", limitResponse);
            assertTrue("users array should respect limit", limitResponse.users.length <= 1);

            // Clean up
            DeleteUserRequest deleteRequest = new DeleteUserRequest();
            deleteRequest.userId = userId;
            client.deleteUser(deleteRequest).get();
        } catch (Exception e) {
            System.out.println(e.getMessage());

            fail("should not throw any exception");
        }
    }

    @Test
    public void testQueryUserActions() {
        String userId = UUID.randomUUID().toString();

        EnrollVerifiedAuthenticatorRequest enrollRequest = new EnrollVerifiedAuthenticatorRequest();
        enrollRequest.userId = userId;
        enrollRequest.attributes = new EnrollVerifiedAuthenticatorAttributes();
        enrollRequest.attributes.verificationMethod = VerificationMethodType.SMS;
        enrollRequest.attributes.phoneNumber = "+6427000000";

        try {
            EnrollVerifiedAuthenticatorResponse enrollResponse = client.enrollVerifiedAuthenticator(enrollRequest)
                    .get();

            assertNotNull("enrollResponse should exist", enrollResponse);

            // Track an action
            TrackRequest trackRequest = new TrackRequest();
            trackRequest.userId = userId;
            trackRequest.action = "signIn";

            TrackResponse trackResponse = client.track(trackRequest).get();

            assertNotNull("trackResponse should exist", trackResponse);

            // Query user actions
            QueryUserActionsRequest queryRequest = new QueryUserActionsRequest();
            queryRequest.userId = userId;

            QueryUserActionsResponseItem[] actions = client.queryUserActions(queryRequest).get();

            assertNotNull("actions should exist", actions);
            assertTrue("actions should not be empty", actions.length > 0);

            QueryUserActionsResponseItem action = actions[0];
            assertEquals("action code should match", "signIn", action.actionCode);
            assertNotNull("idempotencyKey should exist", action.idempotencyKey);
            assertNotNull("createdAt should exist", action.createdAt);
            assertNotNull("state should exist", action.state);

            // Query with filter by action code
            QueryUserActionsRequest filteredRequest = new QueryUserActionsRequest();
            filteredRequest.userId = userId;
            filteredRequest.actionCodes = new String[] { "signIn" };

            QueryUserActionsResponseItem[] filteredActions = client.queryUserActions(filteredRequest).get();

            assertNotNull("filtered actions should exist", filteredActions);
            assertTrue("filtered actions should not be empty", filteredActions.length > 0);

            for (QueryUserActionsResponseItem filteredAction : filteredActions) {
                assertEquals("all actions should have signIn code", "signIn", filteredAction.actionCode);
            }

            // Query with state filter
            QueryUserActionsRequest stateRequest = new QueryUserActionsRequest();
            stateRequest.userId = userId;
            stateRequest.state = UserActionState.CHALLENGE_REQUIRED;

            QueryUserActionsResponseItem[] stateActions = client.queryUserActions(stateRequest).get();

            assertNotNull("state filtered actions should exist", stateActions);
            // Actions exist if any match the state filter
            if (stateActions.length > 0) {
                assertEquals("action state should match filter", "CHALLENGE_REQUIRED", stateActions[0].state);
            }

            // Clean up
            DeleteUserRequest deleteRequest = new DeleteUserRequest();
            deleteRequest.userId = userId;
            client.deleteUser(deleteRequest).get();
        } catch (Exception e) {
            System.out.println(e.getMessage());

            fail("should not throw any exception");
        }
    }
}
