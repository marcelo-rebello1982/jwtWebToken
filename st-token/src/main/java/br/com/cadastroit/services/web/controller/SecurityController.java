package br.com.cadastroit.services.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.cadastroit.services.config.domain.User;
import io.swagger.annotations.ApiKeyAuthDefinition;
import io.swagger.annotations.ApiKeyAuthDefinition.ApiKeyLocation;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

@CrossOrigin
@RestController
@RequestMapping(path = "auth/security")
public class SecurityController {

	private final MongoTemplate mongoTemplate;
	private final PasswordEncoder encoder;

	@Autowired
	public SecurityController(MongoTemplate mongoTemplate,
							  PasswordEncoder encoder){
		this.mongoTemplate = mongoTemplate;
		this.encoder 	   = encoder;
	}


	@ApiOperation(value = "Retrieves user data after validating username")
	@PostMapping("/user-profile")
	public ResponseEntity<Object> userProfile(@ApiParam(value = "Para validacao do registro, informe as credenciais do usuario (Username / Password)")
		    @RequestBody User user) {
		try {
			User userProfile = this.mongoTemplate.findOne(new Query(Criteria.where("username").is(user.getUsername())),User.class);
			if(userProfile != null) {
				boolean match = encoder.matches(user.getPassword(), userProfile.getPassword());
				if(match){
					return ResponseEntity.ok(userProfile);
				} else {
					return ResponseEntity.status(HttpStatus.FORBIDDEN).body(String.format("Credenciais invalidas para o usuario %s", user.getUsername()));
				}
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(String.format("Registro invalido..."));
			}
		}catch(Exception ex) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(String.format("Erro no path '/user-profile'. [Erro] = %s", ex.getMessage()));
		}
	}
	
	@ApiOperation(value = "Retrieves user data from token")
	@PostMapping("/user-token")
	public ResponseEntity<Object> userByToken(
			@ApiKeyAuthDefinition(description = "JWT token.", name = "token", in = ApiKeyLocation.HEADER, key = "Bearer")
			@RequestHeader("Authorization") String token) {
		try {	
			String key = token.replace("Bearer", "").trim();
			User userProfile = this.mongoTemplate.findOne(new Query(Criteria.where("token").is(key)),User.class);
			if(userProfile != null) {
				long expire 			= userProfile.getExpireAtDate();
				long currentTimeMillis 	= System.currentTimeMillis();
				
				if(currentTimeMillis > expire) {
					return ResponseEntity.status(HttpStatus.FORBIDDEN).body(String.format("Credencial invalida, %s...", token));
				} else {
					return ResponseEntity.ok(userProfile);
				}
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(String.format("Credencial invalida, %s...", token));
			}
		}catch(Exception ex) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(String.format("Erro no path '/user-token'. [Erro] = %s", ex.getMessage()));
		}
	}
}
