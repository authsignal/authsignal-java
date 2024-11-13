package com.authsignal.model;

public class EnrollVerifiedAuthenticatorRequestBody extends ApiModel {
  public VerificationMethodType verificationMethod;
  public String phoneNumber;
  public String email;
  public Boolean isDefault;
}