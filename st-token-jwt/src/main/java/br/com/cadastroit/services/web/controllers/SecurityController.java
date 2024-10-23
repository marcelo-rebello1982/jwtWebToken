package br.com.cadastroit.services.web.controllers;

import br.com.cadastroit.services.config.security.model.UserDetailsJwt;
import br.com.cadastroit.services.web.controllers.dto.JwtRequest;
import io.swagger.annotations.ApiKeyAuthDefinition;
import io.swagger.annotations.ApiKeyAuthDefinition.ApiKeyLocation;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin
@RestController
@RequestMapping(path = "security")
public class SecurityController {

	@Autowired
	private MongoTemplate mongoTemplate;

	@ApiOperation(value = "Check username inside database and returns full profile ")
	@PostMapping("/user-profile")
	public ResponseEntity<Object> userProfile(
			@ApiKeyAuthDefinition(description = "Token was provided by JWT System.", name = "token", in = ApiKeyLocation.HEADER, key = "Bearer")
			@RequestHeader("Authorization") String token,
			@ApiParam(value = "A username that should be validate whether exists or not. Fill object with only username.")
		    @RequestBody JwtRequest jwtRequest) {
		try {
			String jwtToken = token.replace("Bearer", "").trim();
			UserDetailsJwt userDetailsJwt = this.mongoTemplate.findOne(new Query(Criteria.where("username").is(jwtRequest.getUsername())),UserDetailsJwt.class);
			if(userDetailsJwt != null) {
				if(jwtToken.equals(userDetailsJwt.getJwttoken())){
					return ResponseEntity.ok(userDetailsJwt);
				} else {
					return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Token that was used isn't associated to this user "+jwtRequest.getUsername()+".[Token] = "+jwtToken);
				}
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("User "+jwtRequest.getUsername()+" was not found...");
			}
		}catch(Exception ex) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error on get userProfile, [error] = "+ex.getMessage());
		}
	}
	
	@ApiOperation(value = "Check token inside database and returns full profile ")
	@PostMapping("/user-token")
	public ResponseEntity<Object> userToken(
			@ApiKeyAuthDefinition(description = "Token was provided by JWT System.", name = "token", in = ApiKeyLocation.HEADER, key = "Bearer")
			@RequestHeader("Authorization") String token) {
		try {	
			String jwtToken = token.replace("Bearer", "").trim();
			UserDetailsJwt userDetailsJwt = this.mongoTemplate.findOne(new Query(Criteria.where("jwttoken").is(jwtToken)),UserDetailsJwt.class);
			if(userDetailsJwt != null) {
				long expire 			= userDetailsJwt.getExpire();
				long currentTimeMillis 	= System.currentTimeMillis();
				
				if(currentTimeMillis > expire) {
					return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Token that was used is unavailable. [Token] = "+jwtToken);
				} else {
					return ResponseEntity.ok(userDetailsJwt);
				}
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Token "+token+" was not found...");
			}
		}catch(Exception ex) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error on get userProfile, [error] = "+ex.getMessage());
		}
	}
}
