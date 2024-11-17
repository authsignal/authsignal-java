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
  CHALLENGE_FAILED,

  @SerializedName("REVIEW_REQUIRED")
  REVIEW_REQUIRED,

  @SerializedName("REVIEW_SUCCEEDED")
  REVIEW_SUCCEEDED,

  @SerializedName("REVIEW_FAILED")
  REVIEW_FAILED
}
