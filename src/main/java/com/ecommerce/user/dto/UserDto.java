package com.ecommerce.user.dto;

import com.ecommerce.user.entity.User;
import com.ecommerce.user.enums.UserRole;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserDto {
    private Long id;
    private String email;
    private String name;
    private byte[] img;

    private UserRole userRole;
    private String token;

    // Convert Entity -> DTO
    public static UserDto fromEntity(User user) {
        if (user == null) {
            return null;
        }
        return UserDto.builder()
                .id(user.getId()).img(user.getImg())
                .email(user.getEmail())
                .name(user.getName())
                .userRole(user.getUserRole())
                .build();
    }

    // Convert DTO -> Entity
    public User toEntity() {
        return User.builder()
                .id(this.id)
                .email(this.email)
                .name(this.name).img(this.getImg())
                .userRole(this.userRole)
                .build();
    }
}
