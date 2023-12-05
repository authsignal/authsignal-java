package com.authsignal;

import org.junit.Test;

import com.authsignal.exception.AuthsignalException;
import com.authsignal.model.*;

import static org.junit.Assert.*;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class AuthsignalClientTest {
  private final String baseURL = "https://api.authsignal.com/v1";
  private final String secret = "";
  private final String userId = "3efdac26-fbac-4043-b5a2-5a02c2e63364";
  private final String action = "test-action";

  private AuthsignalClient client = new AuthsignalClient(secret, baseURL);

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
