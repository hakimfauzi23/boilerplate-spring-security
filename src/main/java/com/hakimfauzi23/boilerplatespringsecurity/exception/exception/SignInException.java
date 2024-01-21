package com.hakimfauzi23.boilerplatespringsecurity.exception.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class SignInException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public SignInException(String message) {
        super(message);
    }
}
