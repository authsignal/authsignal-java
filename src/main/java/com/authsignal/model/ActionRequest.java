package com.authsignal.model;

public class ActionRequest extends ApiModel {
    public String userId;
    public String action;
    public String idempotencyKey;
}
