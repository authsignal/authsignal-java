package com.authsignal.model;

public class TrackRequest extends APIModel {
  public String userId;
  public String action;
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
}
