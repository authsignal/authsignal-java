package com.authsignal.model;

import java.util.Map;

public class WebhookLogEvent {
    public int version;
    public String type;
    public String id;
    public String source;
    public String time;
    public String tenantId;
    public Map<String, Object> record;
}
