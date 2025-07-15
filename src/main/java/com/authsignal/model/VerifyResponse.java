package com.authsignal.model;

public class VerifyResponse extends ApiModel {
    public boolean isVerified;
    public String email;
    public String phoneNumber;
    public VerificationMethodType verificationMethod;
}