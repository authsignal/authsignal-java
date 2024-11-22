package com.authsignal.model;

public class GetActionResponse extends ApiModel {
    public UserActionState state;
    public String createdAt;
    public String stateUpdatedAt;
    public String verificationMethod;
    public Rule[] rules;
}
