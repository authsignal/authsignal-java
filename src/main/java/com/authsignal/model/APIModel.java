package com.authsignal.model;

import com.google.gson.Gson;

class APIModel {
  public String toString() {
    return new Gson().toJson(this);
  }
}
