package com.authsignal.model;

import java.util.Map;

public class UserAttributes extends ApiModel {
    public String email;
    public String phoneNumber;
    public String username;
    public String displayName;
    public Map<String, Object> custom;
    public VerificationMethodType defaultVerificationMethod;
}
