package com.authsignal.model;

public class UserAgent {
    public String ua;
    public UserAgentBrowser browser;
    public UserAgentDevice device;
    public UserAgentEngine engine;
    public UserAgentOs os;
    public UserAgentCpu cpu;
}

class UserAgentBrowser {
    public String name;
    public String version;
    public String major;
}

class UserAgentDevice {
    public String model;
    public String type;
    public String vendor;
}

class UserAgentEngine {
    public String name;
    public String version;
}

class UserAgentOs {
    public String name;
    public String version;
}

class UserAgentCpu {
    public String architecture;
}