package com.authsignal.model;

public class EnrollVerifiedAuthenticatorResponse {
  public UserAuthenticator authenticator;
  public String[] recoveryCodes;
}

class UserAuthenticator {
  public String userId;
  public String userAuthenticatorId;
  public AuthenticatorType authenticatorType;
  public String createdAt;
  public String verifiedAt;
  public Boolean isDefault;
  public Boolean isActive;
  public OobChannel oobChannel;
  public String phoneNumber;
  public String email;
}
