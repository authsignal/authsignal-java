package com.authsignal.model;

public class EnrollVerifiedAuthenticatorRequest {
  public String userId;
  public OobChannel oobChannel;
  public String phoneNumber;
  public String email;
  public Boolean isDefault;
}