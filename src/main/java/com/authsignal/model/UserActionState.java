package com.authsignal.model;

import com.google.gson.annotations.SerializedName;

public enum UserActionState {
  @SerializedName("ALLOW")
  ALLOW,

  @SerializedName("BLOCK")
  BLOCK,

  @SerializedName("CHALLENGE_REQUIRED")
  CHALLENGE_REQUIRED,

  @SerializedName("CHALLENGE_SUCCEEDED")
  CHALLENGE_SUCCEEDED,

  @SerializedName("CHALLENGE_FAILED")
  CHALLENGE_FAILED
}
