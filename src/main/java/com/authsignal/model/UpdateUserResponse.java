package com.authsignal.model;

import java.util.Map;

public class UpdateUserResponse extends ApiModel {
    public String userId;
    public String email;
    public String phoneNumber;
    public String username;
    public String displayName;
    public Map<String, String> custom;
}
