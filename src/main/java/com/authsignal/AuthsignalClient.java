package com.authsignal;

import com.authsignal.exception.*;
import com.authsignal.model.*;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

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

  public CompletableFuture<UpdateUserResponse> updateUser(UpdateUserRequest request) throws AuthsignalException {
    String path = String.format("/users/%s", request.userId);

    UpdateUserRequestBody body = new UpdateUserRequestBody();

    body.email = request.email;
    body.phoneNumber = request.phoneNumber;
    body.username = request.username;
    body.displayName = request.displayName;

    return postRequest(path, new Gson().toJson(body))
        .thenApply(response -> new Gson().fromJson(response.body(), UpdateUserResponse.class));
  }

  public CompletableFuture<UserAuthenticator[]> getAuthenticators(UserRequest request) throws AuthsignalException {
    String path = String.format("/users/%s/authenticators", request.userId);

    return getRequest(path).thenApply(
        response -> new Gson().fromJson(response.body(), UserAuthenticator[].class));
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
    body.scope = request.scope;

    return postRequest(path, new Gson().toJson(body))
        .thenApply(response -> new Gson().fromJson(response.body(), TrackResponse.class));
  }

  public CompletableFuture<ActionResponse> getAction(ActionRequest request) throws AuthsignalException {
    String path = String.format("/users/%s/actions/%s/%s", request.userId, request.action, request.idempotencyKey);

    return getRequest(path).thenApply(response -> new Gson().fromJson(response.body(), ActionResponse.class));
  }

  public CompletableFuture<ValidateChallengeResponse> validateChallenge(ValidateChallengeRequest request)
      throws AuthsignalException {

    return postRequest("/validate", new Gson().toJson(request))
        .thenApply(response -> new Gson().fromJson(response.body(), ValidateChallengeResponse.class));
  }

  public CompletableFuture<EnrollVerifiedAuthenticatorResponse> enrollVerifiedAuthenticator(
      EnrollVerifiedAuthenticatorRequest request) throws AuthsignalException {
    String path = String.format("/users/%s/authenticators", request.userId);

    EnrollVerifiedAuthenticatorRequestBody body = new EnrollVerifiedAuthenticatorRequestBody();

    body.verificationMethod = request.verificationMethod;
    body.email = request.email;
    body.phoneNumber = request.phoneNumber;
    body.isDefault = request.isDefault;

    return postRequest(path, new Gson().toJson(body))
        .thenApply(response -> new Gson().fromJson(response.body(), EnrollVerifiedAuthenticatorResponse.class));
  }

  public CompletableFuture<DeleteAuthenticatorResponse> deleteAuthenticator(DeleteAuthenticatorRequest request)
      throws AuthsignalException {
    String path = String.format("/users/%s/authenticators/%s", request.userId, request.userAuthenticatorId);

    return deleteRequest(path)
        .thenApply(response -> new Gson().fromJson(response.body(), DeleteAuthenticatorResponse.class));
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

  private CompletableFuture<HttpResponse<String>> deleteRequest(String path) throws AuthsignalException {
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
        .DELETE()
        .build();

    return client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
  }

  private String getBasicAuthHeader() {
    return "Basic " + Base64.getEncoder().encodeToString((this._secret + ":").getBytes());
  }
}
