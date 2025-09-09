package edu.microservicio.microservicio_perfil.service;

import edu.microservicio.microservicio_perfil.dto.LoginRequest;
import edu.microservicio.microservicio_perfil.dto.ProfileDetailsResponse;
import edu.microservicio.microservicio_perfil.dto.ProviderRegistrationRequest;
import edu.microservicio.microservicio_perfil.dto.TokenResponse;
import edu.microservicio.microservicio_perfil.dto.UserRegistrationRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.Base64;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeycloakService {

    @Value("${keycloak.auth-server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    private final RestTemplate restTemplate;

    /**
     * Authenticate user and obtain tokens from Keycloak
     * @param loginRequest from user
     * @return TokenResponse with access and refresh tokens
     */
    public TokenResponse authenticate(LoginRequest loginRequest) {
        try {
            String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token",
                    keycloakServerUrl, realm);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "password");
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("username", loginRequest.getUsername());
            body.add("password", loginRequest.getPassword());
            body.add("scope", "openid profile email");

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> responseBody = response.getBody();
                return new TokenResponse(
                        (String) responseBody.get("access_token"),
                        (String) responseBody.get("refresh_token"),
                        (String) responseBody.get("token_type"),
                        (Integer) responseBody.get("expires_in")
                );
            }
        } catch (Exception e) {
            log.error("Error authenticating user: {}", e.getMessage());
            throw new RuntimeException("Authentication failed", e);
        }
        throw new RuntimeException("Authentication failed");
    }

    /**
     * Register a new user in Keycloak and assign roles
     * @param userRequest with user details
     * @return Success message or error
     */
    public String registerUser(UserRegistrationRequest userRequest) {
        try {
            String adminToken = getAdminToken();
            String usersUrl = String.format("%s/admin/realms/%s/users", keycloakServerUrl, realm);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(adminToken);

            Map<String, Object> userRepresentation = createUserRepresentation(
                    userRequest.getUsername(),
                    userRequest.getEmail(),
                    userRequest.getFirstName(),
                    userRequest.getLastName(),
                    userRequest.getPassword()
            );

            // Add user type attribute
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("user_type", Arrays.asList("USER"));
            attributes.put("age", Arrays.asList(String.valueOf(userRequest.getAge())));
            attributes.put("photo", Arrays.asList(Base64.getEncoder().encodeToString(userRequest.getPhoto())));
            attributes.put("description", Arrays.asList(userRequest.getDescription()));

            userRepresentation.put("attributes", attributes);

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(userRepresentation, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(usersUrl, request, String.class);

            if (response.getStatusCode() == HttpStatus.CREATED) {
                // Extract user ID from Location header and assign roles
                String locationHeader = response.getHeaders().getFirst("Location");
                if (locationHeader != null) {
                    String userId = locationHeader.substring(locationHeader.lastIndexOf("/") + 1);
                    assignUserRoles(userId, UserType.USER);
                }
                return "User registered successfully";
            }
        } catch (Exception e) {
            log.error("Error registering user: {}", e.getMessage());
            throw new RuntimeException("User registration failed", e);
        }
        throw new RuntimeException("User registration failed");
    }

    /**
     * Register a new provider in Keycloak and assign roles
     * @param providerRequest with provider details
     * @return Success message or error
     */
    public String registerProvider(ProviderRegistrationRequest providerRequest) {
        try {
            String adminToken = getAdminToken();
            String usersUrl = String.format("%s/admin/realms/%s/users", keycloakServerUrl, realm);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(adminToken);

            Map<String, Object> userRepresentation = createUserRepresentation(
                    providerRequest.getUsername(),
                    providerRequest.getEmail(),
                    providerRequest.getFirstName(),
                    providerRequest.getLastName(),
                    providerRequest.getPassword()
            );

            // Add provider-specific attributes
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("user_type", Arrays.asList("PROVIDER"));
            attributes.put("age", Arrays.asList(String.valueOf(providerRequest.getAge())));
            attributes.put("photo", Arrays.asList(Base64.getEncoder().encodeToString(providerRequest.getPhoto())));
            attributes.put("description", Arrays.asList(providerRequest.getDescription()));
            attributes.put("phone", Arrays.asList(providerRequest.getPhone()));
            attributes.put("web_page", Arrays.asList(providerRequest.getWebPage()));
            attributes.put("social_media_contact", Arrays.asList(providerRequest.getSocialMediaContact()));
            userRepresentation.put("attributes", attributes);

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(userRepresentation, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(usersUrl, request, String.class);

            if (response.getStatusCode() == HttpStatus.CREATED) {
                // Extract user ID from Location header and assign roles
                String locationHeader = response.getHeaders().getFirst("Location");
                if (locationHeader != null) {
                    String userId = locationHeader.substring(locationHeader.lastIndexOf("/") + 1);
                    assignUserRoles(userId, UserType.PROVIDER);
                }
                return "Provider registered successfully";
            }
        } catch (Exception e) {
            log.error("Error registering provider: {}", e.getMessage());
            throw new RuntimeException("Provider registration failed", e);
        }
        throw new RuntimeException("Provider registration failed");
    }

    /**
     * Create user representation for Keycloak API
     * @param username
     * @param email
     * @param firstName
     * @param lastName
     * @param password
     * @return Map representing the user
     */
    private Map<String, Object> createUserRepresentation(String username, String email, 
                                                        String firstName, String lastName, String password) {
        Map<String, Object> userRepresentation = new HashMap<>();
        userRepresentation.put("username", username);
        userRepresentation.put("email", email);
        userRepresentation.put("firstName", firstName);
        userRepresentation.put("lastName", lastName);
        userRepresentation.put("enabled", true);
        userRepresentation.put("emailVerified", true);

        // Set password
        Map<String, Object> credential = new HashMap<>();
        credential.put("type", "password");
        credential.put("value", password);
        credential.put("temporary", false);
        userRepresentation.put("credentials", Arrays.asList(credential));

        return userRepresentation;
    }

    /**
     * Obtain admin access token for Keycloak admin API to register users
     * @return admin access token
     */
    private String getAdminToken() {
        try {
            // Updated endpoint for Keycloak 26.x
            String tokenUrl = String.format("%s/realms/master/protocol/openid-connect/token", keycloakServerUrl);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "password");
            body.add("client_id", "admin-cli");
            body.add("username", "admin"); // Configure admin credentials
            body.add("password", "admin"); // Configure admin credentials

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                return (String) response.getBody().get("access_token");
            }
        } catch (Exception e) {
            log.error("Error getting admin token: {}", e.getMessage());
            throw new RuntimeException("Failed to get admin token", e);
        }
        throw new RuntimeException("Failed to get admin token");
    }

    /**
     * Assign roles to a user in the shared microservices realm
     * @param userId
     * @param userType
     */
    public void assignUserRoles(String userId, UserType userType) {
        try {
            String adminToken = getAdminToken();
            String userRolesUrl = String.format("%s/admin/realms/%s/users/%s/role-mappings/realm", 
                    keycloakServerUrl, realm, userId);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(adminToken);

            // Get available roles
            List<Map<String, Object>> rolesToAssign = new ArrayList<>();
            
            if (userType == UserType.USER) {
                rolesToAssign.addAll(getRoleRepresentations(adminToken, Arrays.asList("USER")));
            } else if (userType == UserType.PROVIDER) {
                rolesToAssign.addAll(getRoleRepresentations(adminToken, Arrays.asList("PROVIDER")));
            }

            HttpEntity<List<Map<String, Object>>> request = new HttpEntity<>(rolesToAssign, headers);
            restTemplate.postForEntity(userRolesUrl, request, String.class);

        } catch (Exception e) {
            log.error("Error assigning roles to user: {}", e.getMessage());
        }
    }

    /**
     * Get role representations by role names
     * @param adminToken
     * @param roleNames
     * @return List of role representations
     */
    private List<Map<String, Object>> getRoleRepresentations(String adminToken, List<String> roleNames) {
        List<Map<String, Object>> roles = new ArrayList<>();
        
        for (String roleName : roleNames) {
            try {
                String roleUrl = String.format("%s/admin/realms/%s/roles/%s", 
                        keycloakServerUrl, realm, roleName);

                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(adminToken);
                HttpEntity<String> request = new HttpEntity<>(headers);

                ResponseEntity<Map> response = restTemplate.exchange(roleUrl, HttpMethod.GET, request, Map.class);
                
                if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                    roles.add(response.getBody());
                }
            } catch (Exception e) {
                log.warn("Role {} not found or could not be retrieved: {}", roleName, e.getMessage());
            }
        }
        
        return roles;
    }

    /**
     * Validate token across microservices ecosystem
     * @param token
     * @return true if valid, false otherwise
     */
    public boolean validateToken(String token) {
        try {
            String introspectionUrl = String.format("%s/realms/%s/protocol/openid-connect/token/introspect", 
                    keycloakServerUrl, realm);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setBasicAuth(clientId, clientSecret);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("token", token);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(introspectionUrl, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                return (Boolean) response.getBody().getOrDefault("active", false);
            }
        } catch (Exception e) {
            log.error("Error validating token: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Get user info from token
     * @param token of the user
     * @return ProfileDetailsResponse with user info
     */
    public ProfileDetailsResponse getProfileDetails(String token) {
        try {
            String adminToken = getAdminToken();
            String userInfoUrl = String.format("%s/admin/realms/%s/", 
                    keycloakServerUrl, realm);

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);

            HttpEntity<String> request = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(userInfoUrl, HttpMethod.GET, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                ProfileDetailsResponse profileDetails = new ProfileDetailsResponse();
                profileDetails.setUsername((String) response.getBody().get("preferred_username"));
                profileDetails.setEmail((String) response.getBody().get("email"));
                profileDetails.setFirstName((String) response.getBody().get("given_name"));
                profileDetails.setLastName((String) response.getBody().get("family_name"));
                profileDetails.setAge((Integer) response.getBody().get("age"));
                profileDetails.setPhoto((String) response.getBody().get("picture"));
                profileDetails.setDescription((String) response.getBody().get("description"));
                return profileDetails;
            }
        } catch (Exception e) {
            log.error("Error fetching user info: {}", e.getMessage());
        }
        return new ProfileDetailsResponse();
    }

    /**
     * Get user details from JWT token claims (recommended for performance)
     * @param accessToken JWT access token
     * @return User details from token claims
     */
    public ProfileDetailsResponse getUserDetailsFromToken(String accessToken) {
        try {
            // Decode JWT token without verification (for demo - in production use proper JWT library)
            String[] tokenParts = accessToken.split("\\.");
            if (tokenParts.length != 3) {
                throw new RuntimeException("Invalid JWT token format");
            }
            
            // Base64 decode the payload
            String payload = new String(Base64.getDecoder().decode(tokenParts[1]));
            
            // Parse JSON manually or use Jackson ObjectMapper
            // This is a simplified approach - you should use a proper JWT library
            log.info("JWT Payload: {}", payload);
            
            return ProfileDetailsResponse.builder()
                .message("User details extracted from JWT token")
                .data(payload)
                .build();
            
        } catch (Exception e) {
            log.error("Error extracting user details from token: {}", e.getMessage());
            throw new RuntimeException("Failed to extract user details from token", e);
        }
    }

    /**
     * Get user details from Keycloak UserInfo endpoint (standard OIDC)
     * @param accessToken JWT access token
     * @return User details from UserInfo endpoint
     */
    public ProfileDetailsResponse getUserDetailsFromUserInfo(String accessToken) {
        try {
            String userInfoUrl = String.format("%s/realms/%s/protocol/openid-connect/userinfo", 
                    keycloakServerUrl, realm);

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);

            HttpEntity<String> request = new HttpEntity<>(headers);

            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    userInfoUrl, HttpMethod.GET, request, 
                    new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {});

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> userInfo = response.getBody();
                
                return ProfileDetailsResponse.builder()
                    .message("User details from UserInfo endpoint")
                    .data(userInfo)
                    .build();
            }
        } catch (Exception e) {
            log.error("Error getting user info: {}", e.getMessage());
            throw new RuntimeException("Failed to get user info", e);
        }
        throw new RuntimeException("Failed to get user info");
    }

    /**
     * Introspect token to get user details (alternative method)
     * @param accessToken JWT access token to introspect
     * @return Token introspection response with user details
     */
    public ProfileDetailsResponse introspectToken(String accessToken) {
        try {
            String introspectUrl = String.format("%s/realms/%s/protocol/openid-connect/token/introspect", 
                    keycloakServerUrl, realm);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setBasicAuth(clientId, clientSecret);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("token", accessToken);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    introspectUrl, HttpMethod.POST, request,
                    new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {});

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> introspectionResult = response.getBody();
                
                return ProfileDetailsResponse.builder()
                    .message("Token introspection result")
                    .data(introspectionResult)
                    .build();
            }
        } catch (Exception e) {
            log.error("Error introspecting token: {}", e.getMessage());
            throw new RuntimeException("Failed to introspect token", e);
        }
        throw new RuntimeException("Failed to introspect token");
    }

    /**
     * Enum for user types in the microservices ecosystem
     */
    public enum UserType {
        USER, PROVIDER
    }
}
