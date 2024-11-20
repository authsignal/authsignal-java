package com.authsignal.model;

import com.google.gson.Gson;

class ApiModel {
    public String toString() {
        return new Gson().toJson(this);
    }
}
