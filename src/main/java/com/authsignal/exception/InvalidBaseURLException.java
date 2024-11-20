package com.authsignal.exception;

public class InvalidBaseURLException extends Exception {
    public InvalidBaseURLException() {
        super("The base URL format is invalid.");
    }
}
