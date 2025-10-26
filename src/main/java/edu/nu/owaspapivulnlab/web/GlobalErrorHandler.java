package edu.nu.owaspapivulnlab.web;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

// FIXED(API7: Security Misconfiguration): limited sensitive error details in responses
@ControllerAdvice
public class GlobalErrorHandler {

    // FIX: Avoid exposing exception class names and detailed internal messages to clients.
    // Return a generic message for unexpected errors.
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> all(Exception e) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Internal Server Error");
        errorMap.put("message", "An unexpected error occurred. Please contact support if the issue persists.");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorMap);
    }

    // FIX: Hide database-specific messages that could leak schema or SQL information.
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> db(DataAccessException e) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Database Error");
        errorMap.put("message", "A database operation failed. Please try again later.");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMap);
    }
}
