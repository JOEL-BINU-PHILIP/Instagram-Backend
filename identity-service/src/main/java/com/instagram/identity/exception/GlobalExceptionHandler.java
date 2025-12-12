package com.instagram.identity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * GlobalExceptionHandler catches exceptions thrown across the entire application.
 *
 * Benefits:
 *  - Keeps controller code clean
 *  - Ensures all errors return consistent responses
 *
 * @RestControllerAdvice tells Spring:
 *    "Whenever a controller throws an exception, send it here."
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handles all RuntimeExceptions.
     *
     * Example:
     *  - "User already exists"
     *  - "Invalid refresh token"
     *
     * It returns a simple BAD_REQUEST (400) response with the message.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<?> handleRuntime(RuntimeException ex) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ex.getMessage());
    }
}
