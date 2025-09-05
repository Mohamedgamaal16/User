package com.ecommerce.user.repos;


import com.ecommerce.user.entity.User;
import com.ecommerce.user.enums.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepo extends JpaRepository<User,Long > {

Optional<User> findFirstByEmail (String email);
    User  findByUserRole (UserRole userRole);
}
