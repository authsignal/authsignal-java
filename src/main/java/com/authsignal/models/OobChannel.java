package com.authsignal.models;

import com.google.gson.annotations.SerializedName;

public enum OobChannel {
  @SerializedName("SMS")
  SMS,

  @SerializedName("EMAIL_MAGIC_LINK")
  EMAIL_MAGIC_LINK,
}
