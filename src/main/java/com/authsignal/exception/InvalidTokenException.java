package com.authsignal.exception;

public class InvalidTokenException extends AuthsignalException {
  public InvalidTokenException() {
    super("INVALID_TOKEN");
  }
}