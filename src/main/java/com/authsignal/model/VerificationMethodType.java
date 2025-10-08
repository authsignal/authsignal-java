package com.authsignal.model;

import com.google.gson.annotations.SerializedName;

public enum VerificationMethodType {
    @SerializedName("SMS")
    SMS,

    @SerializedName("AUTHENTICATOR_APP")
    AUTHENTICATOR_APP,

    @SerializedName("EMAIL_MAGIC_LINK")
    EMAIL_MAGIC_LINK,

    @SerializedName("EMAIL_OTP")
    EMAIL_OTP,

    @SerializedName("PUSH")
    PUSH,

    @SerializedName("SECURITY_KEY")
    SECURITY_KEY,

    @SerializedName("PASSKEY")
    PASSKEY,

    @SerializedName("VERIFF")
    VERIFF,

    @SerializedName("IPROOV")
    IPROOV,

    @SerializedName("PALM_BIOMETRICS_RR")
    PALM_BIOMETRICS_RR,

    @SerializedName("IDVERSE")
    IDVERSE,

    @SerializedName("DEVICE")
    DEVICE,

    @SerializedName("WHATSAPP")
    WHATSAPP,
}
