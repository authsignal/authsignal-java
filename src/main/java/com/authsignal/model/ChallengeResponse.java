package com.authsignal.model;

public class ChallengeResponse extends ApiModel {
    public String challengeId;
    public String idempotencyKey;
    public Long expiresAt;
    public Integer retryAfterSeconds;
}