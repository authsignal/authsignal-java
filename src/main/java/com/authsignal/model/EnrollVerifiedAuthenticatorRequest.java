package com.authsignal.model;

public class EnrollVerifiedAuthenticatorRequest extends ApiModel {
    public String userId;
    public VerificationMethodType verificationMethod;
    public String phoneNumber;
    public String email;
    public Boolean isDefault;
}