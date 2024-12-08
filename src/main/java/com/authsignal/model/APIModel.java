package com.authsignal.model;

import java.io.Serializable;

import com.google.gson.Gson;

class ApiModel implements Serializable {
    public String toString() {
        return new Gson().toJson(this);
    }
}
