package edu.microservicio.microservicio_perfil.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ProfileDetailsResponse {
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private int age;
    private String photo;
    private String description;
    private String message;
    private Object data; // Generic field for different response types
}
