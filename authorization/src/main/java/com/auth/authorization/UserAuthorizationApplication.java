package com.auth.authorization;

import com.auth.authorization.security.JwtProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(JwtProperties.class)
public class UserAuthorizationApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserAuthorizationApplication.class, args);
	}

}
