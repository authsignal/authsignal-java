package com.authsignal;

import com.authsignal.models.*;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import net.minidev.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.Base64;

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

    public UserResponse getUser(UserRequest request) throws URISyntaxException, IOException, InterruptedException {
        String path = String.format("/users/%s", request.userId);

        HttpResponse<String> response = getRequest(path);

        return new Gson().fromJson(response.body(), UserResponse.class);
    }

    public TrackResponse track(TrackRequest request) throws URISyntaxException, IOException, InterruptedException {
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

        HttpResponse<String> response = postRequest(path, new Gson().toJson(body));

        return new Gson().fromJson(response.body(), TrackResponse.class);
    }

    public ActionResponse getAction(ActionRequest request)
            throws URISyntaxException, IOException, InterruptedException {
        String path = String.format("/users/%s/actions/%s/%s", request.userId, request.action, request.idempotencyKey);

        HttpResponse<String> response = getRequest(path);

        return new Gson().fromJson(response.body(), ActionResponse.class);
    }

    public ValidateChallengeResponse validateChallenge(ValidateChallengeRequest request)
            throws URISyntaxException, IOException, InterruptedException, ParseException, JOSEException {

        ValidateChallengeResponse response = new ValidateChallengeResponse();

        JWSVerifier verifier = new MACVerifier(_secret);

        SignedJWT parsedJWT = SignedJWT.parse(request.token);

        Boolean isValid = parsedJWT.verify(verifier);

        if (!isValid) {
            response.success = false;

            return response;
        }

        JWTClaimsSet claims = parsedJWT.getJWTClaimsSet();

        String userId = claims.getSubject();

        if (request.userId != null && !request.userId.equals(userId)) {
            response.success = false;

            return response;
        }

        JSONObject other = claims.getJSONObjectClaim("other");
        String action = other.getAsString("actionCode");
        String idempotencyKey = other.getAsString("idempotencyKey");

        ActionRequest actionRequest = new ActionRequest();
        actionRequest.userId = userId;
        actionRequest.action = action;
        actionRequest.idempotencyKey = idempotencyKey;

        ActionResponse actionResponse = getAction(actionRequest);

        response.success = actionResponse.state == UserActionState.CHALLENGE_SUCCEEDED;
        response.state = actionResponse.state;
        response.userId = userId;

        return response;
    }

    public EnrollVerifiedAuthenticatorResponse enrollVerifiedAuthenticator(EnrollVerifiedAuthenticatorRequest request)
            throws URISyntaxException, IOException, InterruptedException {
        String path = String.format("/users/%s/authenticators", request.userId);

        EnrollVerifiedAuthenticatorRequestBody body = new EnrollVerifiedAuthenticatorRequestBody();

        body.oobChannel = request.oobChannel;
        body.email = request.email;
        body.phoneNumber = request.phoneNumber;
        body.isDefault = request.isDefault;

        HttpResponse<String> response = postRequest(path, new Gson().toJson(body));

        return new Gson().fromJson(response.body(), EnrollVerifiedAuthenticatorResponse.class);
    }

    private HttpResponse<String> getRequest(String path) throws URISyntaxException, IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(_baseURL + path))
                .header("Authorization", getBasicAuthHeader())
                .GET()
                .build();

        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postRequest(String path, String body)
            throws URISyntaxException, IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(_baseURL + path))
                .header("Authorization", getBasicAuthHeader())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private String getBasicAuthHeader() {
        return "Basic " + Base64.getEncoder().encodeToString((this._secret + ":").getBytes());
    }
}
