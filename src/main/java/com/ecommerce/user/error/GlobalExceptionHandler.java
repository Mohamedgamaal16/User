package com.ecommerce.user.error;



import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Date;

@ControllerAdvice
public class GlobalExceptionHandler {


    @ExceptionHandler(UserApiException.class)
    public ResponseEntity<?> handelApiException(UserApiException ex){

        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                ex.getMessage(),
                new Date()
        ) ;

        return new ResponseEntity<>(errorResponse,HttpStatus.SERVICE_UNAVAILABLE);
    }
}