package com.authsignal.exception;

public class AuthsignalException extends Exception {
    int statusCode;
    String errorCode;
    String errorDescription;

    public AuthsignalException(int statusCode, String errorCode, String errorDescription) {
        super(formatMessage(statusCode, errorCode, errorDescription));

        this.statusCode = statusCode;
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    private static String formatMessage(int statusCode, String errorCode, String errorDescription) {
        String description = formatDescription(errorCode, errorDescription);

        return String.format("AuthsignalException: %d - %s", statusCode, description);
    }

    private static String formatDescription(String errorCode, String errorDescription) {
        return errorDescription != null && errorDescription.length() > 0 ? errorDescription : errorCode;
    }
}
