package com.authsignal.exception;

public class InvalidURLFormatException extends AuthsignalException {
    public InvalidURLFormatException() {
        super(500, "invalid_url", "The URL format is invalid.");
    }
}
