package com.gkcontas.auth.dto;

import com.gkcontas.auth.model.Role;
import com.gkcontas.auth.model.User;
import java.time.Instant;
import java.util.List;

public record UserResponse(Long id, String email, List<String> roles, Instant createdAt) {

    public static UserResponse of(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getRoles().stream().map(Role::getName).sorted().toList(),
                user.getCreatedAt()
        );
    }
}
