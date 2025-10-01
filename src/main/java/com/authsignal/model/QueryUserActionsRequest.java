package com.authsignal.model;

public class QueryUserActionsRequest extends ApiModel {
    public String userId;
    public String fromDate;
    public String[] actionCodes;
    public UserActionState state;
}

