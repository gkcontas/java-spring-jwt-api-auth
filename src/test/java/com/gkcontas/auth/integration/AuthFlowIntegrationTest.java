package com.gkcontas.auth.integration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gkcontas.auth.model.Role;
import com.gkcontas.auth.model.User;
import com.gkcontas.auth.repository.RoleRepository;
import com.gkcontas.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

class AuthFlowIntegrationTest extends IntegrationTestBase {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Test
    void shouldRegisterLoginAndAccessProfileWithAccessToken() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "alice@example.com", "password": "supersecret123"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));

        String accessToken = login("alice@example.com", "supersecret123");

        mockMvc.perform(get("/profile").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alice@example.com"));
    }

    @Test
    void shouldRejectDuplicateEmailRegistration() throws Exception {
        registerUser("bob@example.com", "supersecret123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "bob@example.com", "password": "anotherpass123"}
                                """))
                .andExpect(status().isConflict());
    }

    @Test
    void shouldReturnUnauthorizedForProfileWithoutToken() throws Exception {
        mockMvc.perform(get("/profile")).andExpect(status().isUnauthorized());
    }

    @Test
    void shouldReturnUnauthorizedForLoginWithWrongPassword() throws Exception {
        registerUser("carol@example.com", "supersecret123");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "carol@example.com", "password": "wrong-password"}
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldReturnForbiddenForAdminEndpointWithoutAdminRole() throws Exception {
        registerUser("dave@example.com", "supersecret123");
        String accessToken = login("dave@example.com", "supersecret123");

        mockMvc.perform(get("/admin/users").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldAllowAdminEndpointForUserWithAdminRole() throws Exception {
        registerUser("erin@example.com", "supersecret123");
        promoteToAdmin("erin@example.com");

        String accessToken = login("erin@example.com", "supersecret123");

        mockMvc.perform(get("/admin/users").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.email == 'erin@example.com')]").exists());
    }

    @Test
    void shouldExchangeARefreshTokenForNewTokens() throws Exception {
        registerUser("frank@example.com", "supersecret123");
        String loginBody = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "frank@example.com", "password": "supersecret123"}
                                """))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String refreshToken = objectMapper.readTree(loginBody).get("refreshToken").asText();

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\": \"%s\"}".formatted(refreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists());
    }

    @Test
    void shouldRejectRefreshWithAnAccessToken() throws Exception {
        registerUser("grace@example.com", "supersecret123");
        String accessToken = login("grace@example.com", "supersecret123");

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\": \"%s\"}".formatted(accessToken)))
                .andExpect(status().isUnauthorized());
    }

    private void registerUser(String email, String password) throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(email, password)))
                .andExpect(status().isCreated());
    }

    private String login(String email, String password) throws Exception {
        String body = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(email, password)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("accessToken").asText();
    }

    void promoteToAdmin(String email) {
        User user = userRepository.findByEmail(email).orElseThrow();
        Role adminRole = roleRepository.findByName(Role.ADMIN).orElseThrow();
        user.addRole(adminRole);
        userRepository.save(user);
    }
}
