package com.mediaalterations.authservice.exception;

import lombok.Getter;

@Getter
public class SessionExpiredException extends RuntimeException {

    private final String message;
    private final int statusCode;

    public SessionExpiredException(String message, int statusCode) {
        super(message);
        this.message = message;
        this.statusCode = statusCode;
    }
}
