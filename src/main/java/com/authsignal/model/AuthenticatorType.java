package com.authsignal.model;

import com.google.gson.annotations.SerializedName;

public enum AuthenticatorType {
  @SerializedName("OOB")
  OOB,

  @SerializedName("OTP")
  OTP,
}
