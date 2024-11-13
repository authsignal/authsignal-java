package com.authsignal.model;

import com.google.gson.annotations.SerializedName;

public class ValidateChallengeResponse extends ApiModel{
  public Boolean isValid;
  public UserActionState state;
  public String stateUpdatedAt;
  public String userId;
  @SerializedName(value = "actionCode")
  public String action;
  public String idempotencyKey;
  public String verificationMethod;
}
