package com.authsignal;

import org.junit.Test;

import com.authsignal.models.*;
import com.nimbusds.jose.JOSEException;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.text.ParseException;

public class AuthsignalClientTest {
    private String baseURL = "https://dev-api.authsignal.com/v1";
    private String secret = "UcPsFXS81O3k3xMv9/XBQsjXRc2otwnZ5qGC6jS2DoW6QwXX5FHi0A==";
    private String userId = "5a616356-9a74-4d6d-b3bb-1d6e128f4d6b";
    private String action = "test-action";

    @Test
    public void testSequence()
            throws URISyntaxException, IOException, InterruptedException, ParseException, JOSEException {
        AuthsignalClient client = new AuthsignalClient(secret, baseURL);

        UserRequest userRequest = new UserRequest();
        userRequest.userId = userId;

        UserResponse userResponse = client.getUser(userRequest);

        assertNotNull("user response should exist", userResponse);

        TrackRequest trackRequest = new TrackRequest();
        trackRequest.userId = userId;
        trackRequest.action = action;

        TrackResponse trackResponse = client.track(trackRequest);

        assertNotNull("track should return token", trackResponse.token);

        ValidateChallengeRequest validateChallengeRequest = new ValidateChallengeRequest();
        validateChallengeRequest.token = trackResponse.token;
        validateChallengeRequest.userId = userId;

        ValidateChallengeResponse validateChallengeResponse = client.validateChallenge(validateChallengeRequest);

        assertEquals(
                "state should be allow",
                validateChallengeResponse.state,
                UserActionState.ALLOW);
    }
}
