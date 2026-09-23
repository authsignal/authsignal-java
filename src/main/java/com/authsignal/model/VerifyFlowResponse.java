package com.authsignal.model;

public class VerifyFlowResponse extends ApiModel {
    public FlowAction action;
    public AuthenticationSession session;
    public FlowUser user;
}
