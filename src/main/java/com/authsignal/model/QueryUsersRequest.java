package com.authsignal.model;

public class QueryUsersRequest extends ApiModel {
    public String username;
    public String email;
    public String phoneNumber;
    public String token;
    public Integer limit;
    public String lastEvaluatedUserId;
}

