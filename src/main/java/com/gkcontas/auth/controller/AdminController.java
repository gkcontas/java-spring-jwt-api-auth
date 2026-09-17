package com.gkcontas.auth.controller;

import com.gkcontas.auth.dto.UserResponse;
import com.gkcontas.auth.repository.UserRepository;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Every endpoint here requires the ROLE_ADMIN authority — enforced by
 * {@code SecurityConfig}, not by anything in this class.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final UserRepository userRepository;

    public AdminController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/users")
    public List<UserResponse> listUsers() {
        return userRepository.findAll().stream().map(UserResponse::of).toList();
    }
}
