package com.authsignal.model;

public class UpdateActionRequest extends ApiModel {
    public String userId;
    public String action;
    public String idempotencyKey;
    public ActionAttributes attributes;
}
