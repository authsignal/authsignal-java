package com.authsignal.model;

public class TrackResponse {
  public UserActionState state;
  public String idempotencyKey;
  public String url;
  public String token;
  public Boolean isEnrolled;
  public VerificationMethodType[] allowedVerificationMethods;
  public VerificationMethodType[] enrolledVerificationMethods;
  public VerificationMethodType defaultVerificationMethod;
}
