package com.ecommerce.user.services.jwt;

import com.ecommerce.user.entity.User;
import com.ecommerce.user.error.UserApiException;
import com.ecommerce.user.repos.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserDetailesSerivceImpl implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepo.findFirstByEmail(username)
                .orElseThrow(() -> new UserApiException("No user found with email: " + username));

        // Map role from entity → Spring Security authority
        String role = "ROLE_" + user.getUserRole().name(); // e.g., ROLE_ADMIN or ROLE_CUSTOMER

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                List.of(new SimpleGrantedAuthority(role)) // ✅ add authority
        );
    }
}
