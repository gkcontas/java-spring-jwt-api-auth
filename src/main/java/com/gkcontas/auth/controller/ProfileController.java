package com.gkcontas.auth.controller;

import com.gkcontas.auth.dto.UserResponse;
import com.gkcontas.auth.model.User;
import com.gkcontas.auth.repository.UserRepository;
import java.security.Principal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProfileController {

    private final UserRepository userRepository;

    public ProfileController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/profile")
    public UserResponse profile(Principal principal) {
        User user = userRepository.findByEmail(principal.getName())
                .orElseThrow(() -> new IllegalStateException("Authenticated user no longer exists: " + principal.getName()));
        return UserResponse.of(user);
    }
}
