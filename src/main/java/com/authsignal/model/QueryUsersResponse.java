package com.authsignal.model;

public class QueryUsersResponse extends ApiModel {
    public QueryUsersResponseUser[] users;
    public String lastEvaluatedUserId;
    public Object tokenPayload;
}

