package com.authsignal.model;

public class UserAuthenticator extends APIModel {
  public String userId;
  public String userAuthenticatorId;
  public VerificationMethodType verificationMethod;
  public String createdAt;
  public String verifiedAt;
  public String phoneNumber;
  public String email;
}