package com.authsignal.model;

public class EnrollVerifiedAuthenticatorResponse extends ApiModel {
  public UserAuthenticator authenticator;
  public String[] recoveryCodes;
}
