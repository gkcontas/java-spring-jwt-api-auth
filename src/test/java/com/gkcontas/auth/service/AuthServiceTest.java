package com.gkcontas.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.gkcontas.auth.dto.LoginRequest;
import com.gkcontas.auth.dto.RefreshRequest;
import com.gkcontas.auth.dto.RegisterRequest;
import com.gkcontas.auth.exception.EmailAlreadyRegisteredException;
import com.gkcontas.auth.exception.InvalidCredentialsException;
import com.gkcontas.auth.exception.InvalidTokenException;
import com.gkcontas.auth.model.Role;
import com.gkcontas.auth.model.User;
import com.gkcontas.auth.repository.RoleRepository;
import com.gkcontas.auth.repository.UserRepository;
import com.gkcontas.auth.security.JwtService;
import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final JwtService jwtService =
            new JwtService("test-secret-value-that-is-long-enough-for-hs512-signing", Duration.ofMinutes(15), Duration.ofDays(7));

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(userRepository, roleRepository, passwordEncoder, authenticationManager, jwtService);
    }

    @Test
    void shouldRegisterNewUserWithDefaultRole() {
        when(userRepository.existsByEmail("alice@example.com")).thenReturn(false);
        when(roleRepository.findByName(Role.USER)).thenReturn(Optional.of(new Role(Role.USER)));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        var response = authService.register(new RegisterRequest("alice@example.com", "supersecret123"));

        assertThat(response.email()).isEqualTo("alice@example.com");
        assertThat(response.roles()).containsExactly(Role.USER);
    }

    @Test
    void shouldRejectRegistrationWithAlreadyUsedEmail() {
        when(userRepository.existsByEmail("alice@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(new RegisterRequest("alice@example.com", "supersecret123")))
                .isInstanceOf(EmailAlreadyRegisteredException.class);
    }

    @Test
    void shouldLoginAndReturnAccessAndRefreshTokens() {
        User user = new User("alice@example.com", passwordEncoder.encode("supersecret123"));
        user.addRole(new Role(Role.USER));
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));

        var response = authService.login(new LoginRequest("alice@example.com", "supersecret123"));

        assertThat(response.accessToken()).isNotBlank();
        assertThat(response.refreshToken()).isNotBlank();
    }

    @Test
    void shouldRejectLoginWithBadCredentials() {
        org.mockito.Mockito.doThrow(new BadCredentialsException("bad credentials"))
                .when(authenticationManager).authenticate(any());

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice@example.com", "wrong")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void shouldRefreshUsingAValidRefreshToken() {
        User user = new User("alice@example.com", "hash");
        user.addRole(new Role(Role.USER));
        String refreshToken = jwtService.generateRefreshToken(user);
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));

        var response = authService.refresh(new RefreshRequest(refreshToken));

        assertThat(response.accessToken()).isNotBlank();
        assertThat(response.refreshToken()).isNotBlank();
    }

    @Test
    void shouldRejectRefreshWhenGivenAnAccessTokenInstead() {
        User user = new User("alice@example.com", "hash");
        user.addRole(new Role(Role.USER));
        String accessToken = jwtService.generateAccessToken(user);

        assertThatThrownBy(() -> authService.refresh(new RefreshRequest(accessToken)))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void shouldRejectRefreshWithAGarbageToken() {
        assertThatThrownBy(() -> authService.refresh(new RefreshRequest("not-a-jwt")))
                .isInstanceOf(InvalidTokenException.class);
    }
}
