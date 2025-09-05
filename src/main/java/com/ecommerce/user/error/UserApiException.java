package com.ecommerce.user.error;

public class UserApiException extends RuntimeException {
    public UserApiException(String message) {
        super(message);
    }


    public UserApiException() {
        super();
    }

}
