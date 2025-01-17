package org.chhan.ex_jwt.advice;

import org.chhan.ex_jwt.advice.exception.JwtTokenException;
import org.chhan.ex_jwt.auth.filter.JwtAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice(assignableTypes = JwtAuthenticationFilter.class)
public class JwtTokenFilterAdvice {

    @ExceptionHandler(value = JwtTokenException.class)
    public ResponseEntity<?> handleJwtTokenException(JwtTokenException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
    }
}
