package com.ecommerce.user.dto;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class SignupRequest {
    private String email;
    private String password;
    private String userName;
    private MultipartFile img; // Optional image

}
