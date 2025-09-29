package edu.microservicio.microservicio_perfil.service;

import edu.microservicio.microservicio_perfil.dto.LoginRequest;
import edu.microservicio.microservicio_perfil.dto.ProviderRegistrationRequest;
import edu.microservicio.microservicio_perfil.dto.TokenResponse;
import edu.microservicio.microservicio_perfil.dto.UserDetailsResponse;
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

    // Constants for attribute names
    private static final String ATTR_USER_TYPE = "userType";
    private static final String ATTR_AGE = "age";
    private static final String ATTR_PHOTO = "photo";
    private static final String ATTR_DESCRIPTION = "description";
    private static final String ATTR_PHONE = "phone";
    private static final String ATTR_WEB_PAGE = "webPage";
    private static final String ATTR_SOCIAL_MEDIA = "socialMediaContact";
    
    // Constants for user properties
    private static final String PROP_USERNAME = "username";
    private static final String PROP_EMAIL = "email";
    private static final String PROP_FIRST_NAME = "firstName";
    private static final String PROP_LAST_NAME = "lastName";
    private static final String PROP_ENABLED = "enabled";

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
            body.add(PROP_USERNAME, loginRequest.getUsername());
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
                    userRequest.getPassword(),
                    "USER",
                    userRequest.getAge(),
                    userRequest.getPhoto(),
                    userRequest.getDescription(),
                    null,
                    null,
                    null
            );

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(userRepresentation, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(usersUrl, request, String.class);

            if (response.getStatusCode() == HttpStatus.CREATED) {
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
                    providerRequest.getPassword(),
                    "PROVIDER",
                    providerRequest.getAge(),
                    providerRequest.getPhoto(),
                    providerRequest.getDescription(),
                    providerRequest.getPhone(),
                    providerRequest.getWebPage(),
                    providerRequest.getSocialMediaContact()
            );

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(userRepresentation, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(usersUrl, request, String.class);

            if (response.getStatusCode() == HttpStatus.CREATED) {
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
     * Create user representation for Keycloak API with all attributes
     * @param username User's username
     * @param email User's email
     * @param firstName User's first name
     * @param lastName User's last name
     * @param password User's password
     * @param userType User type (USER/PROVIDER)
     * @param age User's age
     * @param photo User's photo as byte array
     * @param description User's description
     * @param phone User's phone (nullable, for providers)
     * @param webPage User's web page (nullable, for providers)
     * @param socialMediaContact User's social media (nullable, for providers)
     * @return Map representing the complete user
     */
    private Map<String, Object> createUserRepresentation(String username, String email, 
                                                        String firstName, String lastName, String password,
                                                        String userType, int age, byte[] photo, String description,
                                                        String phone, String webPage, String socialMediaContact) {
        Map<String, Object> userRepresentation = new HashMap<>();
        
        // Standard user properties
        userRepresentation.put(PROP_USERNAME, username);
        userRepresentation.put(PROP_EMAIL, email);
        userRepresentation.put(PROP_FIRST_NAME, firstName);
        userRepresentation.put(PROP_LAST_NAME, lastName);
        userRepresentation.put(PROP_ENABLED, true);
        userRepresentation.put("emailVerified", true);

        // Custom attributes must be nested under "attributes" for Keycloak API
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTR_USER_TYPE, Arrays.asList(userType));
        attributes.put(ATTR_AGE, Arrays.asList(String.valueOf(age)));
        attributes.put(ATTR_PHOTO, Arrays.asList(Base64.getEncoder().encodeToString(photo)));
        attributes.put(ATTR_DESCRIPTION, Arrays.asList(description));
        
        // Provider-specific attributes (only if not null)
        if (phone != null) {
            attributes.put(ATTR_PHONE, Arrays.asList(phone));
        }
        if (webPage != null) {
            attributes.put(ATTR_WEB_PAGE, Arrays.asList(webPage));
        }
        if (socialMediaContact != null) {
            attributes.put(ATTR_SOCIAL_MEDIA, Arrays.asList(socialMediaContact));
        }
        
        userRepresentation.put("attributes", attributes);

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
            body.add("username", "admin"); // TODO: Configure admin credentials
            body.add("password", "admin"); // TODO: Configure admin credentials

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
     * Get user info from token using Admin API to include custom attributes
     * @param token of the user
     * @return UserDetailsResponse with user info including custom attributes
     */
    public UserDetailsResponse getProfileDetails(String token) {
        try {
            // First, get basic user info from UserInfo endpoint to get the user ID
            String userInfoUrl = String.format("%s/realms/%s/protocol/openid-connect/userinfo", 
                    keycloakServerUrl, realm);

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);

            HttpEntity<String> request = new HttpEntity<>(headers);

            ResponseEntity<Map<String, Object>> userInfoResponse = restTemplate.exchange(
                    userInfoUrl, HttpMethod.GET, request, 
                    new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {});

            if (userInfoResponse.getStatusCode() == HttpStatus.OK && userInfoResponse.getBody() != null) {
                Map<String, Object> userInfo = userInfoResponse.getBody();
                String username = (String) userInfo.get("preferred_username");
                return getUserProfileByUsername(username);
            }
        } catch (Exception e) {
            log.error("Error fetching user info: {}", e.getMessage());
        }
        return new UserDetailsResponse();
    }

    /**
     * Get complete user profile by username using Admin API
     * @param adminToken Admin access token
     * @param username Username to search for
     * @return UserDetailsResponse with complete user profile
     */
    public UserDetailsResponse getUserProfileByUsername(String username) {
        try {
            String adminToken = getAdminToken();

            String searchUrl = String.format("%s/admin/realms/%s/users?username=%s&exact=true", 
                    keycloakServerUrl, realm, username);

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            HttpEntity<String> request = new HttpEntity<>(headers);

            ResponseEntity<List<Map<String, Object>>> searchResponse = restTemplate.exchange(
                    searchUrl, HttpMethod.GET, request,
                    new org.springframework.core.ParameterizedTypeReference<List<Map<String, Object>>>() {});

            if (searchResponse.getStatusCode() == HttpStatus.OK && 
                searchResponse.getBody() != null && 
                !searchResponse.getBody().isEmpty()) {
                
                Map<String, Object> userRepresentation = searchResponse.getBody().get(0);
                return mapKeycloakToUserDetailsResponse(userRepresentation);
            }
        } catch (Exception e) {
            log.error("Error getting user profile by username: {}", e.getMessage());
        }
        return new UserDetailsResponse();
    }

    /**
     * Map Keycloak user representation to UserDetailsResponse
     * @param userRepresentation from Keycloak Admin API
     * @return UserDetailsResponse with mapped data including custom attributes
     */
    private UserDetailsResponse mapKeycloakToUserDetailsResponse(Map<String, Object> userRepresentation) {
        UserDetailsResponse.UserDetailsResponseBuilder builder = UserDetailsResponse.builder();

        builder.username((String) userRepresentation.get(PROP_USERNAME));
        builder.email((String) userRepresentation.get(PROP_EMAIL));
        builder.firstName((String) userRepresentation.get(PROP_FIRST_NAME));
        builder.lastName((String) userRepresentation.get(PROP_LAST_NAME));
        
        // Extract custom attributes from nested structure
        Map<String, Object> attributes = (Map<String, Object>) userRepresentation.get("attributes");
        if (attributes != null) {
            builder.age(parseIntegerAttribute(attributes.get(ATTR_AGE)));
            builder.photo(extractAttributeValue(attributes.get(ATTR_PHOTO)));
            builder.description(extractAttributeValue(attributes.get(ATTR_DESCRIPTION)));
            builder.phone(extractAttributeValue(attributes.get(ATTR_PHONE)));
            builder.webPage(extractAttributeValue(attributes.get(ATTR_WEB_PAGE)));
            builder.socialMediaContact(extractAttributeValue(attributes.get(ATTR_SOCIAL_MEDIA)));
        }
        
        builder.message("Complete user profile from Keycloak");

        return builder.build();
    }

    /**
     * Extract string value from Keycloak attribute (which is stored as a list)
     * @param attributeValue from Keycloak attributes map
     * @return String value or null
     */
    private String extractAttributeValue(Object attributeValue) {
        if (attributeValue instanceof List<?> && !((List<?>) attributeValue).isEmpty()) {
            return (String) ((List<?>) attributeValue).get(0);
        }
        return null;
    }

    /**
     * Extract and parse integer value from Keycloak attribute
     * @param attributeValue from Keycloak attributes map
     * @return Integer value or null
     */
    private Integer parseIntegerAttribute(Object attributeValue) {
        String stringValue = extractAttributeValue(attributeValue);
        if (stringValue != null) {
            try {
                return Integer.parseInt(stringValue);
            } catch (NumberFormatException e) {
                log.warn("Could not parse age attribute: {}", stringValue);
            }
        }
        return null;
    }

    /**
     * Enum for user types in the microservices ecosystem
     */
    public enum UserType {
        USER, PROVIDER
    }
}
