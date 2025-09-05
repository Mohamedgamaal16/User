package com.ecommerce.user.entity;
import com.ecommerce.user.enums.UserRole;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.aot.generate.GeneratedTypeReference;

import java.util.UUID;


@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name="users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;


    private String name;

    private String email;
    private String password;

    private UserRole userRole;


    @Lob
    @Column(columnDefinition = "LONGBLOB")
    private byte[] img;

}
