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

public class AuthsignalClientTest {
  private final String userId;
  private final String action;

  private AuthsignalClient client;

  public AuthsignalClientTest() throws FileNotFoundException, IOException {
    Properties localProperties = new Properties();
    localProperties.load(new FileInputStream(System.getProperty("user.dir") + "/local.properties"));

    String secret = localProperties.getProperty("test.secret");
    String baseURL = localProperties.getProperty("test.baseURL");
    userId = localProperties.getProperty("test.userId");
    action = localProperties.getProperty("test.action");

    client = new AuthsignalClient(secret, baseURL);
  }

  @Test
  public void testUserEnrolledWithPasskeyMethod() throws AuthsignalException, InterruptedException, ExecutionException {
    CompletableFuture<Boolean> isValid = testGetUser().thenCompose(userResponse -> {
      assertNotNull("userResponse should exist", userResponse);

      return testGetAuthenticators();
    }).thenCompose(authenticators -> {
      assertNotNull("authenticators should exist", authenticators);
      assertTrue("authenticators not should be empty", authenticators.length == 1);
      assertTrue("verification method should be passkey", authenticators[0].verificationMethod == VerificationMethodType.PASSKEY);

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
