package edu.microservicio.microservicio_perfil;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class MicroservicioPerfilApplication {

	public static void main(String[] args) {
		SpringApplication.run(MicroservicioPerfilApplication.class, args);
	}

}
