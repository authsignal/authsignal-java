package com.authsignal.model;

public class UserAuthenticator extends ApiModel {
    public String userId;
    public String userAuthenticatorId;
    public VerificationMethodType verificationMethod;
    public String createdAt;
    public String verifiedAt;
    public String lastVerifiedAt;
    public String phoneNumber;
    public String email;
    public String username;
    public String displayName;
    public String previousSmsChannel;
    public WebauthnCredential webauthnCredential;
}
