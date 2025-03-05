package com.authsignal.model;

import java.util.HashMap;

public class WebhookEvent {
    public int version;
    public String type;
    public String id;
    public String source;
    public String time;
    public String tenantId;
    public HashMap<String, String> data;
}
