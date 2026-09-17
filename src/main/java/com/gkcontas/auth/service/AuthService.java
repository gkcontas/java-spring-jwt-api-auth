package com.gkcontas.auth.service;

import com.gkcontas.auth.dto.LoginRequest;
import com.gkcontas.auth.dto.RefreshRequest;
import com.gkcontas.auth.dto.RegisterRequest;
import com.gkcontas.auth.dto.TokenResponse;
import com.gkcontas.auth.dto.UserResponse;
import com.gkcontas.auth.exception.EmailAlreadyRegisteredException;
import com.gkcontas.auth.exception.InvalidCredentialsException;
import com.gkcontas.auth.exception.InvalidTokenException;
import com.gkcontas.auth.model.Role;
import com.gkcontas.auth.model.User;
import com.gkcontas.auth.repository.RoleRepository;
import com.gkcontas.auth.repository.UserRepository;
import com.gkcontas.auth.security.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            JwtService jwtService
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public UserResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new EmailAlreadyRegisteredException(request.email());
        }
        Role defaultRole = roleRepository.findByName(Role.USER)
                .orElseThrow(() -> new IllegalStateException("Default role %s is missing".formatted(Role.USER)));

        User user = new User(request.email(), passwordEncoder.encode(request.password()));
        user.addRole(defaultRole);
        userRepository.save(user);

        return UserResponse.of(user);
    }

    public TokenResponse login(LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password()));
        } catch (BadCredentialsException ex) {
            throw new InvalidCredentialsException();
        }

        User user = userRepository.findByEmail(request.email())
                .orElseThrow(InvalidCredentialsException::new);
        return new TokenResponse(jwtService.generateAccessToken(user), jwtService.generateRefreshToken(user));
    }

    public TokenResponse refresh(RefreshRequest request) {
        Claims claims;
        try {
            claims = jwtService.parse(request.refreshToken()).getPayload();
        } catch (JwtException | IllegalArgumentException ex) {
            throw new InvalidTokenException();
        }
        if (!JwtService.REFRESH_TOKEN_TYPE.equals(claims.get(JwtService.TOKEN_TYPE_CLAIM, String.class))) {
            throw new InvalidTokenException();
        }

        User user = userRepository.findByEmail(claims.getSubject())
                .orElseThrow(InvalidTokenException::new);
        return new TokenResponse(jwtService.generateAccessToken(user), jwtService.generateRefreshToken(user));
    }
}
