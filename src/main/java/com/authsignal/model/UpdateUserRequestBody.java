package com.authsignal.model;

import java.util.Map;

public class UpdateUserRequestBody extends ApiModel {
    public String email;
    public String phoneNumber;
    public String username;
    public String displayName;
    public Map<String, String> custom;
}
