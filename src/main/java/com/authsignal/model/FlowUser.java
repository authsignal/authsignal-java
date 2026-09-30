package com.authsignal.model;

public class FlowUser extends ApiModel {
    public String userId;
    public FlowUserAuthenticator[] authenticators;
    public String username;
}
