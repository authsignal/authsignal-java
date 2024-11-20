package com.authsignal.exception;

public class InvalidBaseURLException extends AuthsignalException {
    public InvalidBaseURLException() {
        super(500, "invalid_url", "The base URL format is invalid.");
    }
}
