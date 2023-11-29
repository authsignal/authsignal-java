package com.authsignal.models;

public class EnrollVerifiedAuthenticatorRequestBody {
  public OobChannel oobChannel;
  public String phoneNumber;
  public String email;
  public Boolean isDefault;
}