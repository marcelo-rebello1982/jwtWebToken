package br.com.cadastroit.services;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@EnableAutoConfiguration
@SpringBootApplication
public class StJwtTokenApplication {
	
	public static void main(String[] args) {
		SpringApplication.run(StJwtTokenApplication.class, args);
	}

}
