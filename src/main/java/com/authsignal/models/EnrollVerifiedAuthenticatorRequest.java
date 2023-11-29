package com.authsignal.models;

public class EnrollVerifiedAuthenticatorRequest {
  public String userId;
  public OobChannel oobChannel;
  public String phoneNumber;
  public String email;
  public Boolean isDefault;
}