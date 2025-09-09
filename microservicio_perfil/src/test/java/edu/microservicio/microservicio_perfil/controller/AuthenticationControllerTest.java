package edu.microservicio.microservicio_perfil.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.microservicio.microservicio_perfil.dto.LoginRequest;
import edu.microservicio.microservicio_perfil.dto.TokenResponse;
import edu.microservicio.microservicio_perfil.dto.UserRegistrationRequest;
import edu.microservicio.microservicio_perfil.service.KeycloakService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthenticationController.class)
class AuthenticationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private KeycloakService keycloakService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testRegisterUser_Success() throws Exception {
        UserRegistrationRequest userRequest = new UserRegistrationRequest();
        userRequest.setUsername("testuser");
        userRequest.setEmail("test@example.com");
        userRequest.setFirstName("Test");
        userRequest.setLastName("User");
        userRequest.setPassword("password123");
        userRequest.setAge(25);
        userRequest.setPhoto("test-photo".getBytes());
        userRequest.setDescription("Test description");

        when(keycloakService.registerUser(any(UserRegistrationRequest.class)))
                .thenReturn("User registered successfully");

        mockMvc.perform(post("/auth/register/user")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully"));
    }

    @Test
    void testLogin_Success() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password123");

        TokenResponse mockTokenResponse = new TokenResponse(
                "mock-access-token",
                "mock-refresh-token", 
                "Bearer",
                3600
        );

        when(keycloakService.authenticate(any(LoginRequest.class)))
                .thenReturn(mockTokenResponse);

        mockMvc.perform(post("/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("mock-access-token"));
    }

    @Test
    @WithMockUser(roles = "USER")
    void testGetUserProfile_WithUserRole() throws Exception {
        mockMvc.perform(get("/auth/profile"))
                .andExpect(status().isOk())
                .andExpect(content().string("User profile for: user"));
    }

    @Test
    @WithMockUser(roles = "PROVIDER") 
    void testGetProviderData_WithProviderRole() throws Exception {
        mockMvc.perform(get("/auth/provider"))
                .andExpect(status().isOk())
                .andExpect(content().string("Provider data for: user"));
    }

    @Test
    void testGetUserProfile_Unauthorized() throws Exception {
        mockMvc.perform(get("/auth/profile"))
                .andExpect(status().isUnauthorized());
    }
}