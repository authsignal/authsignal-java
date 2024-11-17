package com.authsignal.model;

public class UpdateActionStateRequest extends ApiModel {
  public String userId;
  public String action;
  public String idempotencyKey;
  public UserActionState state;
}

