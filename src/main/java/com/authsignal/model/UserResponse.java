package com.authsignal.model;

public class UserResponse extends APIModel {
  public String userId;
  public String email;
  public String phoneNumber;
  public Boolean isEnrolled;
  public VerificationMethodType[] allowedVerificationMethods;
  public VerificationMethodType[] enrolledVerificationMethods;
  public VerificationMethodType defaultVerificationMethod;
}
