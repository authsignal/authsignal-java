package com.authsignal.model;

public class EnrollVerifiedAuthenticatorResponse extends APIModel {
  public UserAuthenticator authenticator;
  public String[] recoveryCodes;
}
