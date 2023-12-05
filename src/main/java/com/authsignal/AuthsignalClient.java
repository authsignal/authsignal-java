package com.authsignal;

import com.authsignal.exception.*;
import com.authsignal.model.*;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

public class AuthsignalClient {
  private String _secret;
  private String _baseURL;

  public AuthsignalClient(String secret, String baseURL) {
    this._secret = secret;
    this._baseURL = baseURL;
  }

  public AuthsignalClient(String secret) {
    this._secret = secret;
    this._baseURL = "https://api.authsignal.com/v1";
  }

  public CompletableFuture<UserResponse> getUser(UserRequest request) throws AuthsignalException {
    String path = String.format("/users/%s", request.userId);

    return getRequest(path).thenApply(
        response -> new Gson().fromJson(response.body(), UserResponse.class));
  }

  public CompletableFuture<TrackResponse> track(TrackRequest request) throws AuthsignalException {
    String path = String.format("/users/%s/actions/%s", request.userId, request.action);

    TrackRequestBody body = new TrackRequestBody();

    body.idempotencyKey = request.idempotencyKey;
    body.email = request.email;
    body.phoneNumber = request.phoneNumber;
    body.username = request.username;
    body.redirectUrl = request.redirectUrl;
    body.ipAddress = request.ipAddress;
    body.userAgent = request.userAgent;
    body.deviceId = request.deviceId;
    body.redirectToSettings = request.redirectToSettings;

    return postRequest(path, new Gson().toJson(body))
        .thenApply(response -> new Gson().fromJson(response.body(), TrackResponse.class));

  }

  public CompletableFuture<ActionResponse> getAction(ActionRequest request) throws AuthsignalException {
    String path = String.format("/users/%s/actions/%s/%s", request.userId, request.action, request.idempotencyKey);

    return getRequest(path).thenApply(response -> new Gson().fromJson(response.body(), ActionResponse.class));
  }

  public CompletableFuture<ValidateChallengeResponse> validateChallenge(ValidateChallengeRequest request)
      throws AuthsignalException {

    ValidateChallengeResponse response = new ValidateChallengeResponse();

    Boolean isValid = false;

    String userId;
    String action;
    String idempotencyKey;

    try {
      Claims claims = Jwts.parser()
          .verifyWith(Keys.hmacShaKeyFor(_secret.getBytes()))
          .build()
          .parseSignedClaims(request.token)
          .getPayload();

      userId = claims.getSubject();

      Object otherObj = claims.get("other");

      JsonObject other = new Gson().toJsonTree(otherObj).getAsJsonObject();

      action = other.get("actionCode").getAsString();
      idempotencyKey = other.get("idempotencyKey").getAsString();

      isValid = true;
    } catch (JwtException e) {
      throw new InvalidTokenException();
    }

    if (!isValid) {
      response.success = false;

      return CompletableFuture.completedFuture(response);
    }

    if (request.userId != null && !request.userId.equals(userId)) {
      response.success = false;

      return CompletableFuture.completedFuture(response);
    }

    ActionRequest actionRequest = new ActionRequest();
    actionRequest.userId = userId;
    actionRequest.action = action;
    actionRequest.idempotencyKey = idempotencyKey;

    return getAction(actionRequest).thenApply(actionResponse -> {
      response.success = actionResponse.state == UserActionState.CHALLENGE_SUCCEEDED;
      response.state = actionResponse.state;
      response.userId = userId;

      return response;
    });
  }

  public CompletableFuture<EnrollVerifiedAuthenticatorResponse> enrollVerifiedAuthenticator(
      EnrollVerifiedAuthenticatorRequest request) throws AuthsignalException {
    String path = String.format("/users/%s/authenticators", request.userId);

    EnrollVerifiedAuthenticatorRequestBody body = new EnrollVerifiedAuthenticatorRequestBody();

    body.oobChannel = request.oobChannel;
    body.email = request.email;
    body.phoneNumber = request.phoneNumber;
    body.isDefault = request.isDefault;

    return postRequest(path, new Gson().toJson(body))
        .thenApply(response -> new Gson().fromJson(response.body(), EnrollVerifiedAuthenticatorResponse.class));
  }

  private CompletableFuture<HttpResponse<String>> getRequest(String path) throws AuthsignalException {
    HttpClient client = HttpClient.newHttpClient();

    URI uri;

    try {
      uri = new URI(_baseURL + path);
    } catch (URISyntaxException ex) {
      throw new InvalidBaseURLException();
    }

    HttpRequest request = HttpRequest.newBuilder()
        .uri(uri)
        .header("Authorization", getBasicAuthHeader())
        .GET()
        .build();

    return client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
  }

  private CompletableFuture<HttpResponse<String>> postRequest(String path, String body) throws AuthsignalException {
    HttpClient client = HttpClient.newHttpClient();

    URI uri;

    try {
      uri = new URI(_baseURL + path);
    } catch (URISyntaxException ex) {
      throw new InvalidBaseURLException();
    }

    HttpRequest request = HttpRequest.newBuilder()
        .uri(uri)
        .header("Authorization", getBasicAuthHeader())
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();

    return client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
  }

  private String getBasicAuthHeader() {
    return "Basic " + Base64.getEncoder().encodeToString((this._secret + ":").getBytes());
  }
}
