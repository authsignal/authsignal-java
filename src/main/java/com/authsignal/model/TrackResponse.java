package com.authsignal.model;

public class TrackResponse extends ApiModel {
    public String idempotencyKey;
    public UserActionState state;
    public String url;
    public String token;
    public Boolean isEnrolled;
    public VerificationMethodType[] allowedVerificationMethods;
    public VerificationMethodType[] enrolledVerificationMethods;
    public VerificationMethodType defaultVerificationMethod;
}
