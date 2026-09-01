package com.authsignal;

import com.authsignal.model.GetUserRequest;
import com.authsignal.model.TrackAttributes;
import com.authsignal.model.TrackRequest;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;

public class RetryTests {
    private HttpServer server;
    private String apiUrl;

    @Before
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        apiUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @After
    public void tearDown() {
        server.stop(0);
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @Test
    public void retriesSafeRequestsTwiceOn5xx() {
        AtomicInteger attempts = new AtomicInteger();
        server.createContext("/users/user", exchange -> {
            int attempt = attempts.incrementAndGet();
            respond(exchange, attempt < 3 ? 503 : 200, attempt < 3 ? "{\"error\":\"unavailable\"}" : "{\"isEnrolled\":false}");
        });
        server.start();

        GetUserRequest request = new GetUserRequest();
        request.userId = "user";
        new AuthsignalClient("secret", apiUrl).getUser(request).join();

        assertEquals(3, attempts.get());
    }

    @Test
    public void retries429Responses() {
        AtomicInteger attempts = new AtomicInteger();
        server.createContext("/users/user", exchange -> {
            int attempt = attempts.incrementAndGet();
            if (attempt == 1) {
                exchange.getResponseHeaders().set("Retry-After", "0");
            }
            respond(exchange, attempt == 1 ? 429 : 200, attempt == 1 ? "{\"error\":\"rate_limited\"}" : "{\"isEnrolled\":false}");
        });
        server.start();

        GetUserRequest request = new GetUserRequest();
        request.userId = "user";
        new AuthsignalClient("secret", apiUrl).getUser(request).join();

        assertEquals(2, attempts.get());
    }

    @Test
    public void retriesTransientNetworkFailures() {
        AtomicInteger attempts = new AtomicInteger();
        server.createContext("/users/user", exchange -> {
            int attempt = attempts.incrementAndGet();
            if (attempt == 1) {
                exchange.close();
                return;
            }
            respond(exchange, 200, "{\"isEnrolled\":false}");
        });
        server.start();

        GetUserRequest request = new GetUserRequest();
        request.userId = "user";
        new AuthsignalClient("secret", apiUrl).getUser(request).join();

        assertEquals(2, attempts.get());
    }

    @Test
    public void retriesIdempotentWrites() {
        AtomicInteger attempts = new AtomicInteger();
        server.createContext("/users/user/actions/withdrawal", exchange -> {
            int attempt = attempts.incrementAndGet();
            respond(exchange, attempt == 1 ? 503 : 200,
                    attempt == 1 ? "{\"error\":\"unavailable\"}" : "{\"idempotencyKey\":\"key\",\"state\":\"ALLOW\"}");
        });
        server.start();

        TrackAttributes attributes = new TrackAttributes();
        attributes.idempotencyKey = "key";
        TrackRequest request = new TrackRequest();
        request.userId = "user";
        request.action = "withdrawal";
        request.attributes = attributes;
        new AuthsignalClient("secret", apiUrl).track(request).join();

        assertEquals(2, attempts.get());
    }

    @Test
    public void doesNotRetryNonIdempotentWritesOr499() {
        AtomicInteger postAttempts = new AtomicInteger();
        AtomicInteger challengeAttempts = new AtomicInteger();
        server.createContext("/users/user/actions/withdrawal", exchange -> {
            postAttempts.incrementAndGet();
            respond(exchange, 503, "{\"error\":\"unavailable\"}");
        });
        server.createContext("/users/user", exchange -> {
            challengeAttempts.incrementAndGet();
            respond(exchange, 499, "{\"error\":\"challenge_required\"}");
        });
        server.start();

        AuthsignalClient client = new AuthsignalClient("secret", apiUrl);
        TrackRequest trackRequest = new TrackRequest();
        trackRequest.userId = "user";
        trackRequest.action = "withdrawal";
        try {
            client.track(trackRequest).join();
        } catch (CompletionException ignored) {
            // Expected.
        }
        GetUserRequest getUserRequest = new GetUserRequest();
        getUserRequest.userId = "user";
        try {
            client.getUser(getUserRequest).join();
        } catch (CompletionException ignored) {
            // Expected.
        }

        assertEquals(1, postAttempts.get());
        assertEquals(1, challengeAttempts.get());
    }

    @Test
    public void allowsRetriesToBeDisabled() {
        AtomicInteger attempts = new AtomicInteger();
        server.createContext("/users/user", exchange -> {
            attempts.incrementAndGet();
            respond(exchange, 503, "{\"error\":\"unavailable\"}");
        });
        server.start();

        GetUserRequest request = new GetUserRequest();
        request.userId = "user";
        try {
            new AuthsignalClient("secret", apiUrl, 0).getUser(request).join();
        } catch (CompletionException ignored) {
            // Expected.
        }

        assertEquals(1, attempts.get());
    }
}
