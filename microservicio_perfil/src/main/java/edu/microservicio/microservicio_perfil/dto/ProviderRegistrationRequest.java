package edu.microservicio.microservicio_perfil.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProviderRegistrationRequest {
    private String username;
    private String email;
    private String password;
    private String firstName;
    private String lastName;
    private int age;
    private byte[] photo;
    private String description;
    private String phone;
    private String webPage;
    private String socialMediaContact;
}
