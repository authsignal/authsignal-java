package com.authsignal.model;

public class FlowUser extends ApiModel {
    public String userId;
    public FlowUserAuthenticator[] authenticators;
    public String email;
    public String phoneNumber;
    public String username;
    public String displayName;
}
