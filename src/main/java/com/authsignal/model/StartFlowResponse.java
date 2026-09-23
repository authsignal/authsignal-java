package com.authsignal.model;

public class StartFlowResponse extends ApiModel {
    public FlowAction action;
    public String challengeToken;
    public String challengeUrl;
    public FlowUser user;
}
