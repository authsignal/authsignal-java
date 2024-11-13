package com.authsignal.model;

public class ActionRequest extends APIModel {
  public String userId;
  public String action;
  public String idempotencyKey;
}
