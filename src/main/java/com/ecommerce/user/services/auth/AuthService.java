package com.ecommerce.user.services.auth;

import com.ecommerce.user.dto.SignupRequest;
import com.ecommerce.user.dto.UserDto;
import com.ecommerce.user.entity.User;

import java.io.IOException;
import java.util.Optional;

public interface AuthService {
    UserDto createUser(SignupRequest signupRequest) ;
    UserDto createAdminAccount(SignupRequest signupRequest);
    Boolean hasUserWithEmail(String email);

    Optional<User> getUserByEmail(String email);

    Optional<User> getCurrentUser(String token);
}
