package com.authsignal.model;

import com.google.gson.annotations.SerializedName;

public enum OobChannel {
  @SerializedName("SMS")
  SMS,

  @SerializedName("EMAIL_MAGIC_LINK")
  EMAIL_MAGIC_LINK,

  @SerializedName("EMAIL_OTP")
  EMAIL_OTP,
}
