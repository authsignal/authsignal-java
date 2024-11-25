package com.authsignal.model;

public class WebauthnCredential extends ApiModel {
    public String credentialId;
    public String deviceId;
    public String name;
    public String aaguid;
    public AaguidMapping aaguidMapping;
    public boolean credentialBackedUp;
    public String credentialDeviceType;
    public String authenticatorAttachment;
    public UserAgent parsedUserAgent;
}