package com.ecommerce.user.services.auth;

import com.ecommerce.user.dto.SignupRequest;
import com.ecommerce.user.dto.UserDto;
import com.ecommerce.user.entity.User;
import com.ecommerce.user.enums.UserRole;
import com.ecommerce.user.error.UserApiException;
import com.ecommerce.user.repos.UserRepo;
import com.ecommerce.user.services.jwt.UserDetailesSerivceImpl;
import com.ecommerce.user.utils.JwtUtil;
import io.jsonwebtoken.io.IOException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.Optional;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserDetailsService userDetailesSerivce;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public UserDto createUser(SignupRequest signupRequest)  {
        byte[] imageBytes = null;
        if (signupRequest.getImg() != null && !signupRequest.getImg().isEmpty()) {
            MultipartFile img = signupRequest.getImg();
            if (img.getSize() > 5 * 1024 * 1024) {  // max 5MB
                throw new UserApiException("Image size exceeds 5MB limit.");
            }
            String contentType = img.getContentType();
            if (contentType == null || !contentType.startsWith("image/")) {
                throw new UserApiException("Invalid file type. Only images are allowed.");
            }
            // اختياري: استخدم Tika للكشف
            // Tika tika = new Tika(); String detected = tika.detect(img.getBytes()); if (!detected.startsWith("image/")) { throw... }
//            imageBytes = img.getBytes();
        }
        try {
            if (signupRequest.getImg() != null && !signupRequest.getImg().isEmpty()) {
                imageBytes = signupRequest.getImg().getBytes();
            }
        } catch (IOException | java.io.IOException e) {
            throw new UserApiException("Failed to process uploaded image");
        }

        try {
            User user = User.builder()
                    .email(signupRequest.getEmail())
                    .name(signupRequest.getUserName())
                    .password(bCryptPasswordEncoder.encode(signupRequest.getPassword()))
                    .userRole(UserRole.CUSTOMER)
                    .img(imageBytes)
                    .build();

            User createdUser = userRepo.save(user);
            return UserDto.fromEntity(createdUser);
        } catch (Exception e) {
            throw new UserApiException("Failed to create user. Please try again later.");
        }
    }

    @Override
    public Boolean hasUserWithEmail(String email) {
        try {
            return userRepo.findFirstByEmail(email).isPresent();
        } catch (Exception e) {
            throw new UserApiException("Error checking if email exists: " + email);
        }
    }

    @Override
    public UserDto createAdminAccount(SignupRequest signupRequest) {
        if (userRepo.findFirstByEmail(signupRequest.getEmail()).isPresent()) {
            throw new UserApiException("Admin with this email already exists.");
        }

        User user = User.builder()
                .email(signupRequest.getEmail())
                .name(signupRequest.getUserName())
                .password(bCryptPasswordEncoder.encode(signupRequest.getPassword()))
                .userRole(UserRole.ADMIN)
                .build();

        User createdAdmin = userRepo.save(user);
        return UserDto.fromEntity(createdAdmin);
    }

    @PostConstruct
    public void createAdminAcscount() {
        try {
            User adminAccount = userRepo.findByUserRole(UserRole.ADMIN);
            if (adminAccount == null) {
                User user = new User();
                user.setEmail("admin@test.com");
                user.setName("mohamed gamal");
                user.setPassword(bCryptPasswordEncoder.encode("admin"));
                user.setUserRole(UserRole.ADMIN);
                userRepo.save(user);
            }
        } catch (Exception e) {
            throw new UserApiException("Failed to create admin account during initialization");
        }
    }



    @Override
    public Optional<User> getUserByEmail(String email) {
        try {
            return userRepo.findFirstByEmail(email);
        } catch (Exception e) {
            throw new UserApiException("Error fetching user by email: " + email);
        }
    }

    @Override
    public Optional<User> getCurrentUser(String token) {
        try {
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7).trim() : token.trim();
            String email = jwtUtil.extractUserName(cleanToken);  // يحقق التوقيع implicitly

            if (email == null || email.isEmpty()) {
                throw new UserApiException("Invalid token: email not found.");
            }

            UserDetails userDetails = userDetailesSerivce.loadUserByUsername(email);  // أضف هذا (افترض إن userDetailsService متاح via Autowire)
            if (!jwtUtil.validateToken(cleanToken, userDetails)) {  // أضف التحقق الكامل
                throw new UserApiException("Invalid or expired token.");
            }

            return userRepo.findFirstByEmail(email);
        } catch (Exception e) {
            throw new UserApiException("Failed to get current user from token: " + e.getMessage());
        }
    }
}
