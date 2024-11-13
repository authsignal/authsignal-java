package com.authsignal.model;

public class EnrollVerifiedAuthenticatorRequest extends APIModel {
  public String userId;
  public VerificationMethodType verificationMethod;
  public String phoneNumber;
  public String email;
  public Boolean isDefault;
}