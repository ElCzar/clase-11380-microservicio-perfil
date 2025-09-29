package edu.microservicio.microservicio_perfil.controller;

import edu.microservicio.microservicio_perfil.dto.LoginRequest;
import edu.microservicio.microservicio_perfil.dto.ProviderRegistrationRequest;
import edu.microservicio.microservicio_perfil.dto.TokenResponse;
import edu.microservicio.microservicio_perfil.dto.UserDetailsResponse;
import edu.microservicio.microservicio_perfil.dto.UserRegistrationRequest;
import edu.microservicio.microservicio_perfil.service.KeycloakService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final KeycloakService keycloakService;

    /**
     * Get a token from Keycloak
     * @param credentials
     * @return
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest credentials) {
        try {
            TokenResponse tokenResponse = keycloakService.authenticate(credentials);
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Register a normal user in Keycloak
     * @param user
     * @return
     */
    @PostMapping("/register/user")
    public ResponseEntity<String> registerUser(@RequestBody UserRegistrationRequest user) {
        try {
            String result = keycloakService.registerUser(user);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("User registration failed: " + e.getMessage());
        }
    }

    /**
     * Register a provider user in Keycloak
     * @param provider
     * @return
     */
    @PostMapping("/register/provider")
    public ResponseEntity<String> registerProvider(@RequestBody ProviderRegistrationRequest provider) {
        try {
            String result = keycloakService.registerProvider(provider);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Provider registration failed: " + e.getMessage());
        }
    }

    /**
     * Get profile details of the authenticated user
     * @param request HTTP request to extract Authorization header
     * @return ProfileDetailsResponse with user details
     */
    @GetMapping("/profile")
    @PreAuthorize("hasAnyRole('USER', 'PROVIDER')")
    public ResponseEntity<UserDetailsResponse> getProfileDetails(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            UserDetailsResponse userDetails = keycloakService.getProfileDetails(token);
            return ResponseEntity.ok(userDetails);
        }
        return ResponseEntity.badRequest().body(null);
    }

    /**
     * Get user details by username
     * @param username
     * @return UserDetailsResponse with user details
     */
    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('USER', 'PROVIDER')")
    public ResponseEntity<UserDetailsResponse> getUserByUsername(@PathVariable String username) {
        UserDetailsResponse userDetails = keycloakService.getUserProfileByUsername(username);
        if (userDetails != null) {
            return ResponseEntity.ok(userDetails);
        }
        return ResponseEntity.notFound().build();
    }
}