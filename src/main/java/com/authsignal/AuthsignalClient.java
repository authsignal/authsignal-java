package com.authsignal;

import com.authsignal.exception.*;
import com.authsignal.model.*;
import com.google.gson.Gson;

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

    public CompletableFuture<GetUserResponse> getUser(GetUserRequest request) {
        String path = String.format("/users/%s", request.userId);

        return getRequest(path).thenApply(
                response -> new Gson().fromJson(response.body(), GetUserResponse.class));
    }

    public CompletableFuture<UserAttributes> updateUser(UpdateUserRequest request) {
        String path = String.format("/users/%s", request.userId);

        return postRequest(path, new Gson().toJson(request.attributes))
                .thenApply(response -> new Gson().fromJson(response.body(), UserAttributes.class));
    }

    public CompletableFuture<Void> deleteUser(DeleteUserRequest request) {
        String path = String.format("/users/%s", request.userId);

        return deleteRequest(path).thenApply(response -> null);
    }

    public CompletableFuture<UserAuthenticator[]> getAuthenticators(GetAuthenticatorsRequest request) {
        String path = String.format("/users/%s/authenticators", request.userId);

        return getRequest(path)
                .thenApply(response -> new Gson().fromJson(response.body(), UserAuthenticator[].class));
    }

    public CompletableFuture<EnrollVerifiedAuthenticatorResponse> enrollVerifiedAuthenticator(
            EnrollVerifiedAuthenticatorRequest request) {
        String path = String.format("/users/%s/authenticators", request.userId);

        return postRequest(path, new Gson().toJson(request.attributes))
                .thenApply(response -> new Gson().fromJson(response.body(), EnrollVerifiedAuthenticatorResponse.class));
    }

    public CompletableFuture<Void> deleteAuthenticator(DeleteAuthenticatorRequest request) {
        String path = String.format("/users/%s/authenticators/%s", request.userId, request.userAuthenticatorId);

        return deleteRequest(path).thenApply(response -> null);
    }

    public CompletableFuture<TrackResponse> track(TrackRequest request) {
        String path = String.format("/users/%s/actions/%s", request.userId, request.action);

        TrackAttributes attributes = request.attributes != null ? request.attributes : new TrackAttributes();

        return postRequest(path, new Gson().toJson(attributes))
                .thenApply(response -> new Gson().fromJson(response.body(), TrackResponse.class));
    }

    public CompletableFuture<ValidateChallengeResponse> validateChallenge(ValidateChallengeRequest request) {
        return postRequest("/validate", new Gson().toJson(request))
                .thenApply(response -> new Gson().fromJson(response.body(), ValidateChallengeResponse.class));
    }

    public CompletableFuture<GetActionResponse> getAction(GetActionRequest request) {
        String path = String.format("/users/%s/actions/%s/%s", request.userId, request.action, request.idempotencyKey);

        return getRequest(path).thenApply(response -> new Gson().fromJson(response.body(), GetActionResponse.class));
    }

    public CompletableFuture<ActionAttributes> updateAction(UpdateActionRequest request) {
        String path = String.format("/users/%s/actions/%s/%s", request.userId, request.action, request.idempotencyKey);

        return patchRequest(path, new Gson().toJson(request.attributes))
                .thenApply(response -> new Gson().fromJson(response.body(), ActionAttributes.class));
    }

    private CompletableFuture<HttpResponse<String>> getRequest(String path) {
        HttpClient client = HttpClient.newHttpClient();

        URI uri;

        try {
            uri = new URI(_baseURL + path);
        } catch (URISyntaxException ex) {
            CompletableFuture<HttpResponse<String>> future = new CompletableFuture<>();
            future.completeExceptionally(new InvalidURLFormatException());
            return future;
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .header("Authorization", getBasicAuthHeader())
                .GET()
                .build();

        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).thenCompose(response -> {
            if (isSuccessStatusCode(response.statusCode())) {
                return CompletableFuture.completedFuture(response);
            } else {
                CompletableFuture<HttpResponse<String>> future = new CompletableFuture<>();
                future.completeExceptionally(mapToAuthsignalException(response));
                return future;
            }
        });

    }

    private CompletableFuture<HttpResponse<String>> postRequest(String path, String body) {
        HttpClient client = HttpClient.newHttpClient();

        URI uri;

        try {
            uri = new URI(_baseURL + path);
        } catch (URISyntaxException ex) {
            CompletableFuture<HttpResponse<String>> future = new CompletableFuture<>();
            future.completeExceptionally(new InvalidURLFormatException());
            return future;
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .header("Authorization", getBasicAuthHeader())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
    }

    private CompletableFuture<HttpResponse<String>> patchRequest(String path, String body) {
        HttpClient client = HttpClient.newHttpClient();
        URI uri;

        try {
            uri = new URI(_baseURL + path);
        } catch (URISyntaxException ex) {
            CompletableFuture<HttpResponse<String>> future = new CompletableFuture<>();
            future.completeExceptionally(new InvalidURLFormatException());
            return future;
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .header("Authorization", getBasicAuthHeader())
                .header("Content-Type", "application/json")
                .method("PATCH", HttpRequest.BodyPublishers.ofString(body))
                .build();

        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
    }

    private CompletableFuture<HttpResponse<String>> deleteRequest(String path) {
        HttpClient client = HttpClient.newHttpClient();

        URI uri;

        try {
            uri = new URI(_baseURL + path);
        } catch (URISyntaxException ex) {
            CompletableFuture<HttpResponse<String>> future = new CompletableFuture<>();
            future.completeExceptionally(new InvalidURLFormatException());
            return future;
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

    private AuthsignalException mapToAuthsignalException(HttpResponse<String> response) {
        AuthsignalErrorResponse errorResponse = new Gson().fromJson(response.body(), AuthsignalErrorResponse.class);

        return new AuthsignalException(response.statusCode(), errorResponse.error, errorResponse.errorDescription);
    }

    private boolean isSuccessStatusCode(int statusCode) {
        return statusCode >= 200 && statusCode <= 299;
    }
}
