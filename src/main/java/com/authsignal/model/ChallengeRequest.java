package com.authsignal.model;

public class ChallengeRequest extends ApiModel {
    public VerificationMethodType verificationMethod;
    public String action;
    public String email;
    public String phoneNumber;
    public String smsChannel;
}