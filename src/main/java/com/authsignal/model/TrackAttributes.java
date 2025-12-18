package com.authsignal.model;

import java.util.Map;

public class TrackAttributes extends ApiModel {
    public String idempotencyKey;
    public String email;
    public String phoneNumber;
    public String username;
    public String redirectUrl;
    public String ipAddress;
    public String userAgent;
    public String deviceId;
    public String scope;
    public Boolean redirectToSettings;
    public Map<String, Object> custom;
    public String locale;
    public String challengeId;
    public String customDomain;
}
