package com.authsignal.model;

public class GetActionRequest extends ApiModel {
    public String userId;
    public String action;
    public String idempotencyKey;
}
