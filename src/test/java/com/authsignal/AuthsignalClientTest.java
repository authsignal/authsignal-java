package com.authsignal;

import org.junit.Test;

import com.authsignal.exception.AuthsignalException;
import com.authsignal.model.*;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.Properties;
import java.util.UUID;

public class AuthsignalClientTest {
    private final String userId = UUID.randomUUID().toString();
    private final String action = "signIn";
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
    public void testUserEnrolledWithEmailOTP() throws AuthsignalException,
            InterruptedException, ExecutionException {
        CompletableFuture<Boolean> isValid = testEnrollVerifiedAuthenticator().thenCompose(enrollResponse -> {
            assertNotNull("enrollResponse should exist", enrollResponse);

            return testGetUser();
        }).thenCompose(userResponse -> {
            assertNotNull("userResponse should exist", userResponse);
            assertTrue("user should be enrolled", userResponse.isEnrolled);

            return testGetAuthenticators();
        }).thenCompose(authenticators -> {
            assertNotNull("authenticators should exist", authenticators);
            assertTrue("authenticators not should be empty", authenticators.length == 1);
            assertTrue("verification method should be passkey",
                    authenticators[0].verificationMethod == VerificationMethodType.EMAIL_OTP);

            return testTrack();
        }).thenCompose(trackResponse -> {
            assertNotNull("trackResponse should return token", trackResponse.token);

            return testValidateChallenge(trackResponse.token);
        }).thenApply(validateChallengeResponse -> {
            assertTrue("validateChallengeResponse state should be CHALLENGE_REQUIRED",
                    validateChallengeResponse.state == UserActionState.CHALLENGE_REQUIRED);
            assertTrue("validateChallengeResponse action should match",
                    validateChallengeResponse.action.equals(this.action));

            return validateChallengeResponse.isValid;
        });

        System.out.println("isValid: " + isValid.get());
    }

    private CompletableFuture<EnrollVerifiedAuthenticatorResponse> testEnrollVerifiedAuthenticator() {
        EnrollVerifiedAuthenticatorRequest enrollRequest = new EnrollVerifiedAuthenticatorRequest();
        enrollRequest.userId = userId;
        enrollRequest.verificationMethod = VerificationMethodType.EMAIL_OTP;
        enrollRequest.email = "test@example.com";

        try {
            return client.enrollVerifiedAuthenticator(enrollRequest);
        } catch (AuthsignalException e) {
            throw new RuntimeException(e);
        }
    }

    private CompletableFuture<UserResponse> testGetUser() {
        UserRequest userRequest = new UserRequest();
        userRequest.userId = userId;

        try {
            return client.getUser(userRequest);
        } catch (AuthsignalException e) {
            throw new RuntimeException(e);
        }
    }

    private CompletableFuture<UserAuthenticator[]> testGetAuthenticators() {
        UserRequest userRequest = new UserRequest();
        userRequest.userId = userId;

        try {
            return client.getAuthenticators(userRequest);
        } catch (AuthsignalException e) {
            throw new RuntimeException(e);
        }
    }

    private CompletableFuture<TrackResponse> testTrack() {
        TrackRequest trackRequest = new TrackRequest();
        trackRequest.userId = userId;
        trackRequest.action = action;

        try {
            return client.track(trackRequest);
        } catch (AuthsignalException e) {
            throw new RuntimeException(e);
        }
    }

    private CompletableFuture<ValidateChallengeResponse> testValidateChallenge(String token) {
        ValidateChallengeRequest validateChallengeRequest = new ValidateChallengeRequest();
        validateChallengeRequest.token = token;

        try {
            return client.validateChallenge(validateChallengeRequest);
        } catch (AuthsignalException e) {
            throw new RuntimeException(e);
        }
    }
}
