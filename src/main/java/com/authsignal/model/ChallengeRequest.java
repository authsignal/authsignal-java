package com.authsignal.model;

import java.util.Map;

public class ChallengeRequest extends ApiModel {
    public VerificationMethodType verificationMethod;
    public String action;
    public String email;
    public String phoneNumber;
    public String smsChannel;
    public String locale;
    public String idempotencyKey;
    public String challengeId;
    public String userId;
    public String deviceId;
    public String ipAddress;
    public String userAgent;
    public Map<String, Object> custom;
    public String scope;
}