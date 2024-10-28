package br.com.cadastroit.services.web.controllers;

import java.util.Optional;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.cadastroit.services.api.services.JwtAuthenticationService;
import br.com.cadastroit.services.config.security.JwtTokenUtil;
import br.com.cadastroit.services.config.security.JwtUserDetailsService;
import br.com.cadastroit.services.config.security.model.UserDetailsJwt;
import br.com.cadastroit.services.config.security.model.UserGroupJwt;
import br.com.cadastroit.services.config.security.model.UserJwtToken;
import br.com.cadastroit.services.web.controllers.dto.JwtRequest;
import br.com.cadastroit.services.web.controllers.dto.JwtResponse;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping(path = "/authenticate/jwtauthentication/auth/user")
@RequiredArgsConstructor
public class JwtAuthenticationController {

	public final MongoTemplate mongoTemplate;
	private final PasswordEncoder passwordEncoder;
	private JwtTokenUtil jwtTokenUtil;
	
	private JwtUserDetailsService jwtUserDetailsService;

	private final JwtAuthenticationService jwtAuthenticationService;

	@ApiOperation(value = "Check username / password and returns a access-token that has 24 hours of validity")
	@PostMapping(value = "/token")
	public ResponseEntity<Object> refreshValidityToken(@ApiParam(required = true, value = "Fill the object JwtRequest with username and password only") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {
			
			Criteria criteria = Criteria.where("username").is(jwtRequest.getUsername());
			UserDetailsJwt userDetailsJwt = this.jwtAuthenticationService.findNoSqlUser(criteria, jwtRequest);
			
			if (this.jwtUserDetailsService.validateUserDetails(userDetailsJwt) && mathPassword(jwtRequest.getPassword(), userDetailsJwt)) {
					
					if (userDetailsJwt.getJwttoken() == null) {
						
						UserJwtToken userJwtToken = this.jwtAuthenticationService.createUserToken(userDetailsJwt, jwtRequest);
						
						return ResponseEntity.ok(new JwtResponse(
											userJwtToken.getToken(),
											userJwtToken.getToken(),
											userJwtToken.getJwtTokenUtil().getExpiration(),
											userJwtToken.getJwtTokenUtil().getDateExpire(),
											""
								));
						
					} else 
						
						return jwtUserDetailsService.dateTokenIsValid(userDetailsJwt)
								
								? ResponseEntity.ok(new JwtResponse(
										userDetailsJwt.getJwttoken(), 
										userDetailsJwt.getJwttoken(),
										userDetailsJwt.getExpire(),
										userDetailsJwt.getDateExpire(),
										""
								))
										
								: ResponseEntity.status(HttpStatus.UNAUTHORIZED)
										.body("Token has expired, please refresh it...");
					
			} else
				
				return errorResponse();
				
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	@ApiOperation(value = "To create a new user, send the username and password in the request body")
	@PostMapping(value = "/create-user")
	public ResponseEntity<Object> createUser(@ApiParam(required = true, value = "Fill the object JwtRequest with username, password and group only. For while, for group use \"user-roles\"") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {

			Criteria criteria = Criteria.where("username").is(jwtRequest.getUsername());
			UserDetailsJwt userDetailsJwt = this.jwtAuthenticationService.findNoSqlUser(criteria, jwtRequest);

			if (userDetailsJwt == null) {

				UserGroupJwt userGroupJwt = this.jwtAuthenticationService.findUserGroup(jwtRequest);
				
				return (validateUserGroup(userGroupJwt))
						
						? ResponseEntity.ok(
								this.mongoTemplate.save(
										this.jwtAuthenticationService.buildJwtUserDetais(userGroupJwt, jwtRequest)) != null
								?
										UserJwtToken.builder()
										.user(jwtRequest.getUsername())
										.group(userGroupJwt.getGroup())
										.daysToExpire(jwtRequest.getDaysToExpire())
										.httpStatus(HttpStatus.OK)
										.httpStatusCode(HttpStatus.OK.value())
										.message("has created successfully...").build()										
								:
										UserJwtToken.builder().message("Error at creating user...").build())
								
						: ResponseEntity.status(HttpStatus.NOT_FOUND).body(
													UserJwtToken.builder()
														.message("User group not found...")
															.build());
				
			} else 
				return ResponseEntity.status(HttpStatus.FORBIDDEN)
											.body("Username " + jwtRequest.getUsername() + " not available...");
			
		} catch (Exception ex) {
			
			return ResponseEntity.status(HttpStatus.FORBIDDEN)
									.body(ex.getMessage());
			
		}
	}
	
	@ApiOperation(value = "To drop user. Inform only username.")
	@DeleteMapping(value = "/drop-user")
	public ResponseEntity<Object> dropUser(@ApiParam(required = true, value = "Fill the object JwtRequest with username only") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {
			
			Criteria criteria = Criteria.where("username").is(jwtRequest.getUsername());
			UserDetailsJwt userDetailsJwt = this.jwtAuthenticationService.findNoSqlUser(criteria, jwtRequest);
			
			if (validateToken(userDetailsJwt) && mathPassword(jwtRequest.getPassword(), userDetailsJwt)) {
				
					return Optional.ofNullable(userDetailsJwt)
						    .map(u -> {
						        this.mongoTemplate.remove(u);
						        return successResponse(userDetailsJwt);
						    }).orElse(errorResponse());
					
				} else return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied, credentials are invalid!");
			
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	@ApiOperation(value = "Check validity from access-token.")
	@PostMapping(value = "/checkvaliditytoken")
	public ResponseEntity<Object> checkvaliditytoken(@ApiParam(required = true, value = "Fill the object JwtRequest with jwttoken only") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {
			
			this.jwtUserDetailsService = this.buildJwtUserDetailsService();
			
			Criteria criteria = Criteria.where("jwttoken").is(jwtRequest.getToken());
			UserDetailsJwt userDetailsJwt = this.jwtAuthenticationService.findNoSqlUser(criteria, jwtRequest);
			jwtRequest.setUsername(userDetailsJwt.getUsername());
			
			if (!this.jwtUserDetailsService.validateUserDetails(userDetailsJwt)) 
				return errorResponse();
			
			if (this.jwtUserDetailsService.validateUserDetails(userDetailsJwt) && this.jwtUserDetailsService.dateTokenIsValid(userDetailsJwt)) {
				
				return ResponseEntity.ok(
									new JwtResponse(
											userDetailsJwt.getJwttoken(), 
											userDetailsJwt.getJwttoken(),
											Long.valueOf(userDetailsJwt.getExpire()),
											userDetailsJwt.getDateExpire(), 
											"credentials are valid!")
						);
				
			} else
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(JwtResponse.builder()
																			.message("Access Denied, credentials are invalid!")
																			.dateExpire(userDetailsJwt.getDateExpire()));
				
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	@ApiOperation(value = "To recovery a token use that endpoint. It's necessary a valid username to request data")
	@PostMapping(value = "/recovery")
	public ResponseEntity<Object> recoveryAuthenticationToken(@ApiParam(required = true, value = "Fill the object JwtRequest with username and password only") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {
			
			Criteria criteria = Criteria.where("username").is(jwtRequest.getUsername());
			UserDetailsJwt userDetailsJwt = this.jwtAuthenticationService.findNoSqlUser(criteria, jwtRequest);
			
			if ( !validateToken(userDetailsJwt) || ( !mathPassword(jwtRequest.getPassword(), userDetailsJwt)) )
				
				return errorResponse();

			String token[] = this.jwtAuthenticationService.createUserTokenStr(userDetailsJwt, jwtRequest);
			
			return ResponseEntity.ok(
								JwtResponse.builder()
								.token(token[0])
								.jwttoken(token[0])
								.expire(Long.valueOf(token[1]))
								.dateExpire(token[2])
								.build()
					);
			
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	@ApiOperation(value = "To change password. After that, the user needs to request data to get a new token.")
	@PutMapping(value = "/updatepassword")
	public ResponseEntity<Object> updateUser(@ApiParam(required = true, value = "Fill the object JwtRequest with username and the new password only") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {
			
			Criteria criteria = Criteria.where("username").is(jwtRequest.getUsername());
			UserDetailsJwt userDetailsJwt = this.jwtAuthenticationService.findNoSqlUser(criteria, jwtRequest);
			
			if (userDetailsJwt != null) {
				userDetailsJwt.setPassword(passwordEncoder.encode(jwtRequest.getPassword()));
				userDetailsJwt.setExpire(0l);
				userDetailsJwt.setJwttoken("");
				userDetailsJwt.setDateExpire("");
				this.mongoTemplate.save(userDetailsJwt);
				return ResponseEntity.status(HttpStatus.OK)
						.body("Password has updated successfully...You should recovery your token, the older value that has associated with your user has erased...");
				
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Credentials are invalid...");
			}
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	@ApiOperation(value = "To crypt a password. Use that endpoint following the specs that has used in project.")
	@PostMapping(value = "/ccrypt-decrypt")
	public ResponseEntity<Object> cryptDecryptPassword(@ApiParam(required = true, value = "Fill the object JwtRequest with password only") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {
			return ResponseEntity.ok(this.jwtAuthenticationService.processPassword(jwtRequest));
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}
	
	private ResponseEntity<Object> successResponse(UserDetailsJwt userDetailsJwt) {

		return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY)
				.body(UserJwtToken.builder()
						.user(userDetailsJwt.getUsername())
						.message("User has removed successfully...")
						.httpStatus(HttpStatus.MOVED_PERMANENTLY)
						.httpStatusCode(HttpStatus.MOVED_PERMANENTLY.value())
						.build());
		
	}

	private ResponseEntity<Object> errorResponse() {

		return ResponseEntity.status(HttpStatus.FORBIDDEN)
				.body(UserJwtToken.builder()
		        		.message("Access Denied, credentials are invalid...")
		        		.httpStatus(HttpStatus.FORBIDDEN)
		        		.httpStatusCode(HttpStatus.FORBIDDEN.value())
		        		.build());
	}
	
	private boolean validateUserGroup(UserGroupJwt userGroup) {
		return userGroup != null && userGroup.getGroup() != null;
	}
	
	private boolean validateToken(UserDetailsJwt userDetailsJwt) {
		return this.jwtUserDetailsService.validateUserDetails(userDetailsJwt);
	}
	
	
	private boolean mathPassword(String password, UserDetailsJwt userDetailsJwt) {
		boolean matchPassword = passwordEncoder.matches(password, userDetailsJwt.getPassword());
		return matchPassword;
	}
	
	public JwtUserDetailsService buildJwtUserDetailsService() {

		if (this.jwtUserDetailsService == null) {
			this.jwtUserDetailsService = JwtUserDetailsService.builder().mongoTemplate(this.mongoTemplate).encoder(this.passwordEncoder).build();
		}
		return this.jwtUserDetailsService;
	}
	
	public JwtTokenUtil buildJwtTokenUtil() {

		if (this.jwtTokenUtil == null) {
			this.jwtTokenUtil = JwtTokenUtil.builder().build();
		}
		return jwtTokenUtil;
	}
	
}
