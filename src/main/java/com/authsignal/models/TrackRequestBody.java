package com.authsignal.models;

public class TrackRequestBody {
  public String idempotencyKey;
  public String email;
  public String phoneNumber;
  public String username;
  public String redirectUrl;
  public String ipAddress;
  public String userAgent;
  public String deviceId;
  public Boolean redirectToSettings;
}
