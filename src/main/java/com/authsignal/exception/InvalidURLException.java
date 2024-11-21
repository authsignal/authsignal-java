package com.authsignal.exception;

public class InvalidURLException extends AuthsignalException {
    public InvalidURLException() {
        super(500, "invalid_url", "The URL format is invalid.");
    }
}
