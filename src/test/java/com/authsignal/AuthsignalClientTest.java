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
  public void testAll() throws AuthsignalException, InterruptedException, ExecutionException {
    CompletableFuture<Boolean> success = testGetUser().thenCompose(userResponse -> {
      assertNotNull("userResponse should exist", userResponse);

      return testTrack();
    }).thenCompose(trackResponse -> {
      assertNotNull("trackResponse should return token", trackResponse.token);

      return testValidateChallenge(trackResponse.token);
    }).thenApply(validateChallengeResponse -> {
      assertTrue("validateChallengeResponse state should be ALLOW",
          validateChallengeResponse.state == UserActionState.ALLOW);

      return validateChallengeResponse.success;
    });

    System.out.println("Success: " + success.get());
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
    validateChallengeRequest.userId = userId;

    try {
      return client.validateChallenge(validateChallengeRequest);
    } catch (AuthsignalException e) {
      throw new RuntimeException(e);
    }
  }
}
