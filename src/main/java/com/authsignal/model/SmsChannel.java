package com.authsignal.model;

import com.google.gson.annotations.SerializedName;

public enum SmsChannel {
    @SerializedName("DEFAULT")
    DEFAULT,
    @SerializedName("WHATSAPP")
    WHATSAPP
}