package com.authsignal.model;

public class EnrollVerifiedAuthenticatorRequestBody {
  public OobChannel oobChannel;
  public String phoneNumber;
  public String email;
  public Boolean isDefault;
}