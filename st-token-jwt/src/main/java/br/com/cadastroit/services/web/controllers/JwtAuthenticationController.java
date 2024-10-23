package br.com.cadastroit.services.web.controllers;

import br.com.cadastroit.services.api.services.JwtAuthenticationService;
import br.com.cadastroit.services.config.security.JwtTokenUtil;
import br.com.cadastroit.services.config.security.JwtUserDetailsService;
import br.com.cadastroit.services.config.security.model.UserDetailsJwt;
import br.com.cadastroit.services.config.security.model.UserGroupJwt;
import br.com.cadastroit.services.repository.UserDetailJwtRepository;
import br.com.cadastroit.services.web.controllers.dto.JwtRequest;
import br.com.cadastroit.services.web.controllers.dto.JwtResponse;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/authenticate/jwtauthentication/auth/user")
@RequiredArgsConstructor
public class JwtAuthenticationController {

	public final MongoTemplate mongoTemplate;
	private final PasswordEncoder passwordEncoder;
	public final UserDetailJwtRepository userDetailJwtRepository;
	private JwtTokenUtil jwtTokenUtil;
	private JwtUserDetailsService userDetailsService;

	@Autowired
	private JwtAuthenticationService service;

	@ApiOperation(value = "Check username / password and returns a access-token that has 24 hours of validity")
	@PostMapping(value = "/token")
	public ResponseEntity<Object> createAuthenticationToken(@ApiParam(required = true, value = "Fill the object JwtRequest with username and password only") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {
			long expire = System.currentTimeMillis();
			Criteria criteria = Criteria.where("username").is(jwtRequest.getUsername());
			UserDetailsJwt userDetailsJwt = this.service.findNoSqlUser(this, criteria, jwtRequest);
			if (validateUserDetails(userDetailsJwt)) {
				boolean matchPassword = passwordEncoder.matches(jwtRequest.getPassword(), userDetailsJwt.getPassword());
				if (matchPassword) {
					if (userDetailsJwt.getJwttoken() == null) {
						
						String token = service.createUserToken(this, userDetailsJwt, jwtRequest);
						
						return ResponseEntity.ok(
								new JwtResponse(
										token,
										token,
										jwtTokenUtil().getExpiration(),
										jwtTokenUtil().getDateExpire()));
						
					} else {
						if (userDetailsJwt.getExpire() > expire) {
							return ResponseEntity.ok(new JwtResponse(userDetailsJwt.getJwttoken(), userDetailsJwt.getJwttoken(),
									userDetailsJwt.getExpire(), userDetailsJwt.getDateExpire()));
						} else {
							return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token has expired, please refresh it...");
						}
					}
				} else {
					return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied, credentials are invalid...");
				}
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied, credentials are invalid...");
			}
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	@ApiOperation(value = "To create a new user. Fill group, username and password")
	@PostMapping(value = "/create-user")
	public ResponseEntity<Object> createUser(@ApiParam(required = true, value = "Fill the object JwtRequest with username, password and group only. For while, for group use \"user-roles\"") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {

			Criteria criteria = Criteria.where("username").is(jwtRequest.getUsername());
			UserDetailsJwt userDetailsJwt = this.service.findNoSqlUser(this, criteria, jwtRequest);

			if (userDetailsJwt == null) {

				UserGroupJwt userGroupJwt = this.service.returnUserGroup(jwtRequest);
				
				return (validateUserGroup(userGroupJwt))
						
						? ResponseEntity.ok(
								this.mongoTemplate.save(
										this.service.buildJwtUserDetais(userGroupJwt, jwtRequest)) != null
								? "User " + jwtRequest.getUsername() + " has created successfully..."
								: "Error at creating user...")
						: ResponseEntity.status(HttpStatus.NOT_FOUND).body("User group not found...");
				
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN)
						.body("Username " + jwtRequest.getUsername() + " not available...");
			}
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	@ApiOperation(value = "Check validity from access-token.")
	@PostMapping(value = "/checkvaliditytoken")
	public ResponseEntity<Object> createRefreshToken(@ApiParam(required = true, value = "Fill the object JwtRequest with jwttoken only") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {
			
			Criteria criteria = Criteria.where("jwttoken").is(jwtRequest.getToken());
			UserDetailsJwt userDetailsJwt = this.service.findNoSqlUser(this, criteria, jwtRequest);
			jwtRequest.setUsername(userDetailsJwt.getUsername());

			if (validateUserDetails(userDetailsJwt)) {
				
				String token = service.createUserToken(this, userDetailsJwt, jwtRequest);
				
				return ResponseEntity.ok(new JwtResponse(
								token,
								token,
								jwtTokenUtil().getExpiration(),
								jwtTokenUtil().getDateExpire()
						));
				
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied, credentials are invalid!");
			}
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
			UserDetailsJwt userDetailsJwt = this.service.findNoSqlUser(this, criteria, jwtRequest);
			
			if (!passwordEncoder.matches(jwtRequest.getPassword(), userDetailsJwt.getPassword())) {
			    return ResponseEntity.status(HttpStatus.FORBIDDEN)
			        .body("Access Denied, credentials are invalid...");
			}

			String token = service.createUserToken(this, userDetailsJwt, jwtRequest);
			
			return ResponseEntity.ok(new JwtResponse(
			    token,
			    token,
			    jwtTokenUtil().getExpiration(),
			    jwtTokenUtil().getDateExpire()
			));
			
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	@ApiOperation(value = "To change password. After that, the user needs to request data to get a new token.")
	@PutMapping(value = "/update-password")
	public ResponseEntity<Object> updateUser(@ApiParam(required = true, value = "Fill the object JwtRequest with username and the new password only") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {
			Criteria criteria = Criteria.where("username").is(jwtRequest.getUsername());
			UserDetailsJwt userDetailsJwt = this.service.findNoSqlUser(this, criteria, jwtRequest);
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
			return ResponseEntity.ok(service.processPassword(jwtRequest));
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	@ApiOperation(value = "To drop user. Inform only username.")
	@DeleteMapping(value = "/drop-user")
	public ResponseEntity<Object> dropUser(@ApiParam(required = true, value = "Fill the object JwtRequest with username only") @RequestBody JwtRequest jwtRequest)
			throws Exception {

		try {
			Criteria criteria = Criteria.where("username").is(jwtRequest.getUsername());
			UserDetailsJwt userDetailsJwt = this.service.findNoSqlUser(this, criteria, jwtRequest);
			if (userDetailsJwt != null) {
				this.mongoTemplate.remove(userDetailsJwt);
				return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).body("User has removed successfully...");
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied, credentials are invalid...");
			}
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	public JwtUserDetailsService jwtUserDetailsService() {

		if (this.userDetailsService == null) {
			this.userDetailsService = JwtUserDetailsService.builder().mongoTemplate(this.mongoTemplate).encoder(this.passwordEncoder).build();
		}
		return this.userDetailsService;
	}
	
	private boolean validateUserGroup(UserGroupJwt userGroup) {
		return userGroup != null && userGroup.getGroup() != null;
	}
	
	private boolean validateUserDetails(UserDetailsJwt userDetailsJwt) {
		return userDetailsJwt != null && userDetailsJwt.get_id() != null;
	}
	
	public JwtTokenUtil jwtTokenUtil() {

		if (this.jwtTokenUtil == null) {
			this.jwtTokenUtil = JwtTokenUtil.builder().build();
		}
		return jwtTokenUtil;
	}
}
