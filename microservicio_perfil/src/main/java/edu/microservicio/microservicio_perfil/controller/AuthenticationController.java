package edu.microservicio.microservicio_perfil.controller;

import edu.microservicio.microservicio_perfil.dto.LoginRequest;
import edu.microservicio.microservicio_perfil.dto.ProfileDetailsResponse;
import edu.microservicio.microservicio_perfil.dto.ProviderRegistrationRequest;
import edu.microservicio.microservicio_perfil.dto.TokenResponse;
import edu.microservicio.microservicio_perfil.dto.UserRegistrationRequest;
import edu.microservicio.microservicio_perfil.service.KeycloakService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final KeycloakService keycloakService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest credentials) {
        try {
            TokenResponse tokenResponse = keycloakService.authenticate(credentials);
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/register/user")
    public ResponseEntity<String> registerUser(@RequestBody UserRegistrationRequest user) {
        try {
            String result = keycloakService.registerUser(user);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("User registration failed: " + e.getMessage());
        }
    }

    @PostMapping("/register/provider")
    public ResponseEntity<String> registerProvider(@RequestBody ProviderRegistrationRequest provider) {
        try {
            String result = keycloakService.registerProvider(provider);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Provider registration failed: " + e.getMessage());
        }
    }

    @GetMapping("/profile")
    @PreAuthorize("hasAnyRole('USER', 'PROVIDER')")
    public ResponseEntity<ProfileDetailsResponse> getProfileDetails(Authentication authentication) {
        ProfileDetailsResponse profileDetails = keycloakService.getProfileDetails(authentication.getName());
        return ResponseEntity.ok(profileDetails);
    }

    @GetMapping("/userinfo")
    @PreAuthorize("hasAnyRole('USER', 'PROVIDER')")
    public ResponseEntity<ProfileDetailsResponse> getUserInfo(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extract token from "Bearer TOKEN" format
            String token = authHeader.replace("Bearer ", "");
            ProfileDetailsResponse userInfo = keycloakService.getUserDetailsFromUserInfo(token);
            return ResponseEntity.ok(userInfo);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                ProfileDetailsResponse.builder()
                    .message("Failed to get user info: " + e.getMessage())
                    .build()
            );
        }
    }

    @GetMapping("/token-details")
    @PreAuthorize("hasAnyRole('USER', 'PROVIDER')")
    public ResponseEntity<ProfileDetailsResponse> getTokenDetails(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extract token from "Bearer TOKEN" format
            String token = authHeader.replace("Bearer ", "");
            ProfileDetailsResponse tokenDetails = keycloakService.getUserDetailsFromToken(token);
            return ResponseEntity.ok(tokenDetails);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                ProfileDetailsResponse.builder()
                    .message("Failed to get token details: " + e.getMessage())
                    .build()
            );
        }
    }

    @GetMapping("/introspect")
    @PreAuthorize("hasAnyRole('USER', 'PROVIDER')")
    public ResponseEntity<ProfileDetailsResponse> introspectToken(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extract token from "Bearer TOKEN" format
            String token = authHeader.replace("Bearer ", "");
            ProfileDetailsResponse introspection = keycloakService.introspectToken(token);
            return ResponseEntity.ok(introspection);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                ProfileDetailsResponse.builder()
                    .message("Failed to introspect token: " + e.getMessage())
                    .build()
            );
        }
    }
}
