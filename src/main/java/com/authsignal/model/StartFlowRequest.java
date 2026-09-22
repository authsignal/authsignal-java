package com.authsignal.model;

public class StartFlowRequest extends ApiModel {
    public String actionCode;
    public UserLookup user;
    public ChallengeAttributes attributes;
    public String redirectUrl;
    public String clientId;
}
