package com.authsignal;

public interface RetryListener {
    void onRetry(int attemptNumber, Throwable lastError);
} 