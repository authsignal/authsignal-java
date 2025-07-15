package com.authsignal.model;

public class GetChallengeResponse extends ApiModel {
    public String challengeId;
    public Integer expiresAt;
    public VerificationMethodType verificationMethod;
    public SmsChannel smsChannel;
    public String phoneNumber;
    public String email;
    public String action;
}