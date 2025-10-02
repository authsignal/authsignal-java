package com.authsignal.model;

public class QueryUserActionsResponseItem extends ApiModel {
    public String actionCode;
    public String idempotencyKey;
    public String createdAt;
    public String updatedAt;
    public String state;
    public String stateUpdatedAt;
    public VerificationMethodType verificationMethod;
    public String verifiedByAuthenticatorId;
}

