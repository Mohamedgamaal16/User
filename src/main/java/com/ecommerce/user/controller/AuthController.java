package com.ecommerce.user.controller;

import com.ecommerce.user.dto.AuthenticationRequest;
import com.ecommerce.user.dto.SignupRequest;
import com.ecommerce.user.dto.UserDto;
import com.ecommerce.user.entity.User;
import com.ecommerce.user.error.UserApiException;
import com.ecommerce.user.repos.UserRepo;
import com.ecommerce.user.services.auth.AuthService;
import com.ecommerce.user.utils.JwtUtil;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final UserRepo userRepo;
    private final JwtUtil jwtUtil;
    private final AuthService authService;

    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String HEADER_STRING = "Authorization";

    @ExceptionHandler(RequestNotPermitted.class)
    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    public Map<String, String> handleRateLimitExceeded(RequestNotPermitted ex) {
        Map<String, String> error = new HashMap<>();
        error.put("error", "Too many requests. Please try again later.");
        return error;
    }

    // ---------------------- LOGIN ----------------------

    // ---------------------- LOGIN ----------------------
    @PostMapping("/login")
    @RateLimiter(name = "loginRateLimiter")
    public ResponseEntity<Map<String, Object>> login(@RequestBody AuthenticationRequest authenticationRequest) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authenticationRequest.getEmail(),
                            authenticationRequest.getPassword()
                    )
            );

            UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getEmail());
            Optional<User> optionalUser = userRepo.findFirstByEmail(userDetails.getUsername());

            if (optionalUser.isEmpty()) {
                throw new UserApiException("User not found for email: " + authenticationRequest.getEmail());
            }

            String accessToken = jwtUtil.generatesToken(userDetails.getUsername()); // تعديل من generatesToken
            String refreshToken = jwtUtil.generateRefreshToken(userDetails);

            Map<String, Object> response = new HashMap<>();
            response.put("user", UserDto.fromEntity(optionalUser.get()));
            response.put("accessToken", accessToken);
            response.put("refreshToken", refreshToken);

            return ResponseEntity.ok(response);

        } catch (BadCredentialsException ex) {
            throw new UserApiException("Invalid email or password.");
        } catch (Exception ex) {
            throw new UserApiException("Login failed due to a server error.");
        }
    }

    // ---------------------- SIGN-UP ----------------------
    @PostMapping("/sign-up/user")
    @RateLimiter(name = "signupRateLimiter")
    public ResponseEntity<Map<String, Object>> signUpUser(@RequestBody SignupRequest signupRequest) {
        if (authService.hasUserWithEmail(signupRequest.getEmail())) {
            throw new UserApiException("Email is already registered: " + signupRequest.getEmail());
        }

        UserDto userDto = authService.createUser(signupRequest);
        String accessToken = jwtUtil.generatesToken(userDto.getEmail()); // تعديل من generatesToken
        String refreshToken = jwtUtil.generateRefreshToken(userDetailsService.loadUserByUsername(userDto.getEmail()));

        Map<String, Object> response = new HashMap<>();
        response.put("user", userDto);
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/sign-up/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> signUpAdmin(@RequestBody SignupRequest signupRequest) {
        if (authService.hasUserWithEmail(signupRequest.getEmail())) {
            throw new UserApiException("Email is already registered: " + signupRequest.getEmail());
        }

        UserDto userDto = authService.createAdminAccount(signupRequest);
        String accessToken = jwtUtil.generatesToken(userDto.getEmail()); // تعديل من generatesToken
        String refreshToken = jwtUtil.generateRefreshToken(userDetailsService.loadUserByUsername(userDto.getEmail()));

        Map<String, Object> response = new HashMap<>();
        response.put("user", userDto);
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);

        return ResponseEntity.ok(response);
    }


    // ---------------------- REFRESH TOKEN ----------------------
    @PostMapping("/refresh")
    @RateLimiter(name = "refreshRateLimiter") // إضافة Rate Limiting
    public ResponseEntity<Map<String, String>> refreshToken(@RequestBody Map<String, String> request) {
        try {
            String refreshToken = request.get("refreshToken");
            if (refreshToken == null || refreshToken.isEmpty()) {
                throw new UserApiException("Refresh token is required.");
            }

            String email = jwtUtil.extractUserName(refreshToken);
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);
            if (jwtUtil.validateToken(refreshToken, userDetails)) {
                String newAccessToken = jwtUtil.generatesToken(email); // تعديل من generatesToken
                Map<String, String> response = new HashMap<>();
                response.put("accessToken", newAccessToken);
                response.put("refreshToken", refreshToken); // إرجاع نفس الـ refresh token
                return ResponseEntity.ok(response);
            } else {
                throw new UserApiException("Invalid or expired refresh token.");
            }
        } catch (Exception ex) {
            throw new UserApiException("Failed to refresh token: " + ex.getMessage());
        }
    }

    // ---------------------- GET USER BY EMAIL ----------------------
    @GetMapping("/user/{email}")
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable String email) {
        Optional<User> userOptional = authService.getUserByEmail(email);

        return userOptional
                .map(user -> ResponseEntity.ok(UserDto.fromEntity(user)))
                .orElseThrow(() -> new UserApiException("User not found for email: " + email));

    }


  // ---------------------- GET CURRENT USER ----------------------
    @GetMapping("/user/current")
    public ResponseEntity<UserDto> getCurrentUser(@RequestHeader("Authorization") String authHeader) {
        return authService.getCurrentUser(authHeader)
                .map(user -> ResponseEntity.ok(UserDto.fromEntity(user)))
                .orElseThrow(() -> new UserApiException("User not found for the provided token."));
    }


}
