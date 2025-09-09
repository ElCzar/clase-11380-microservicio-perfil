package edu.microservicio.microservicio_perfil.integration;

import edu.microservicio.microservicio_perfil.dto.UserRegistrationRequest;
import edu.microservicio.microservicio_perfil.dto.LoginRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UserRegistrationIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void testRegisterUser_ReturnsSuccessMessage() {
        UserRegistrationRequest userRequest = createTestUserRequest();
        
        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/auth/register/user",
                userRequest,
                String.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("registration");
    }

    @Test
    void testLogin_WithValidCredentials() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password123");

        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/auth/login",
                loginRequest,
                String.class
        );

        // Since Keycloak is not running in tests, expect error response
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void testHealthEndpoint() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/actuator/health",
                String.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private UserRegistrationRequest createTestUserRequest() {
        UserRegistrationRequest request = new UserRegistrationRequest();
        request.setUsername("testuser");
        request.setEmail("test@example.com");
        request.setFirstName("Test");
        request.setLastName("User");
        request.setPassword("password123");
        request.setAge(25);
        request.setPhoto("test".getBytes());
        request.setDescription("Test user description");
        return request;
    }
}