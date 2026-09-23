package com.authsignal.model;

public class FlowUserAuthenticator extends ApiModel {
    public String userAuthenticatorId;
    public VerificationMethodType verificationMethod;
    public String email;
    public String phoneNumber;
    public String username;
    public String displayName;
}
