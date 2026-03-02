package com.mediaalterations.authservice.exception;

import lombok.Getter;

@Getter
public class UserAlreadyLoggedInException extends RuntimeException {
    private String message;
    private int statusCode;

    public UserAlreadyLoggedInException(String message, int statusCode) {
        super(message);
        this.message = message;
        this.statusCode = statusCode;
    }
}
