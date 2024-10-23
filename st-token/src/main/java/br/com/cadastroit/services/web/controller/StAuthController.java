package br.com.cadastroit.services.web.controller;

import java.text.DateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;

import org.apache.commons.lang.time.DateUtils;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.cadastroit.services.api.services.AuthService;
import br.com.cadastroit.services.config.domain.Authority;
import br.com.cadastroit.services.config.domain.AuthorityUser;
import br.com.cadastroit.services.config.domain.User;
import br.com.cadastroit.services.web.model.AuthDTO;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping(path = "/administracao/auth/user")
@AllArgsConstructor
public class StAuthController {

	private final MongoTemplate mongoTemplate;
	private final PasswordEncoder passwordEncoder;
	private final AuthService service;
	

	@ApiOperation(value = "Create a new user")
	@PostMapping(value = "/create")
	public ResponseEntity<Object> createUser(@ApiParam(required = true, value = "Creating new users. The roles are: Admin, Customer, or User.")
										@RequestBody AuthDTO authDTO) throws Exception {
		
		try {
			User user = this.service.findByUsername(authDTO.getUsername());
			if(user == null) {
				
				Authority authority = this.mongoTemplate.findOne(new Query(Criteria.where("role")
												.is("ROLE_"+authDTO.getRole()
													.toUpperCase())),
														Authority.class);
				
				
				if(authority != null) {
					
					user = User.builder().username(authDTO.getUsername())
							.accountNonExpired(false)
							.accountNonLocked(false)
							.credentialNonExpired(false)
							.enabled(false)
							.uuid(UUID.randomUUID())
							.password(this.passwordEncoder.encode(authDTO.getPassword()))
							.expireInDays(authDTO.getDaysToExpire())
							.dateExpire(service.calculateDaysToExpire(new Date(System.currentTimeMillis() 
											+ (authDTO.getDaysToExpire() * (1000 * 60 * 60 * 24)))))
							.expireAtDate(service.calculateDaysToExpire(authDTO.getDaysToExpire()))
							.build();
					
					user = this.mongoTemplate.save(user);
					
					return user.getId() != null
						    ? ResponseEntity.ok(this.mongoTemplate.save(AuthorityUser.builder()
						        .authority(authority)
						        .user(user)
						        .uuid(UUID.randomUUID())
						        .build()) != null ? "new user registered..." : "")
						    : ResponseEntity.ok("Failed to register user...");
					
				} else {
					return ResponseEntity.status(HttpStatus.NOT_FOUND).body(String.format("Rule could not be found %s...", authDTO.getRole()));
				}
			} else {
				return ResponseEntity.status(HttpStatus.CONFLICT).body(String.format("Username already in use : %s...",authDTO.getUsername()));
			}
		}catch(Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	// ajustar e conferir a questão do token expirado, esta errado a lógica.
	@ApiOperation(value = "Requesting token (Valid for 24 hours if daysToExpire not declared in request body )")
	@PostMapping(value = "/request/token")
	public ResponseEntity<Object> createAuthenticationToken(@ApiParam(required = true, value = "Provide the username and password") @RequestBody AuthDTO authDTO) throws Exception {
		try {
			
			long expire = System.currentTimeMillis();
			User userDTO = this.service.findByUsername(authDTO.getUsername()); // validate user
			
			// ajustar para validar com user/pass
			// User userDTO = this.service.findByUsername(authDTO.getUsername(), passwordEncoder.encode(authDTO.getPassword())); 
			
			if(userDTO != null) {
				boolean matchPassword = passwordEncoder.matches(authDTO.getPassword(), userDTO.getPassword());
				if(matchPassword) {
					if(userDTO.getToken() == null) {
						userDTO = createUserToken(userDTO, authDTO.getDaysToExpire() > 0 ? authDTO.getDaysToExpire() : 1 );
						return ResponseEntity.ok(AuthDTO.builder().token(userDTO.getToken()).dateExpire(userDTO.getDateExpire()).build());
					} else {
					
						return authDTO.getExpire() > expire 
								? ResponseEntity.ok(AuthDTO.builder().token(userDTO.getToken()).dateExpire(userDTO.getDateExpire()).build())
								: ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token expired, access the path '/update/token'...\n Token: [" + userDTO.getToken() +"]");
					}
				} else {
					return ResponseEntity.status(HttpStatus.FORBIDDEN).body("\"Access denied, invalid username or password.");
				}
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("\"Access denied, invalid username or password.");
			}
		}catch(Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}
	
	@ApiOperation(value = "Updating token. If the provided token is valid, a new token is generated and returned to the user.")
	@PostMapping(value = "/update/token")
	public ResponseEntity<Object> createRefreshToken(
			@ApiParam(required = true, value = "Populate the AuthDTO with only the token value")
			@RequestBody AuthDTO authDTO)throws Exception {
		
		try {
			
			User user 		  = this.service.findByToken(authDTO.getToken());
			authDTO.setUsername(user.getUsername());
			boolean matchUser = user != null && user.getId() != null;
			
			return matchUser 
					? ResponseEntity.ok(this.mapUserToDTO(createUserToken(user, 1)))
				    : ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied, invalid username or password...");
			
		}catch(Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}
	
	@ApiOperation(value = "For token recovery. Path for token recovery using username and password.")
	@PostMapping(value = "/recovery/token")
	public ResponseEntity<Object> recoveryAuthenticationToken(
			@ApiParam(required = true, value = "send the AuthDTO object with username and password only.")
			@RequestBody AuthDTO authDTO) throws Exception {
		try {
			User user = this.service.findByUsername(authDTO.getUsername());
			if(user != null && user.getId() != null) {
				
				boolean matchPassword = passwordEncoder.matches(authDTO.getPassword(), user.getPassword());
				
				return matchPassword 
						? ResponseEntity.ok(this.mapUserToDTO(createUserToken(user, 1)))
					    : ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied, invalid username or password...");
				
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied, invalid username or password...");
			}
		}catch(Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}

	@ApiOperation(value = "For password update only")
	@PutMapping(value = "/update/password")
	public ResponseEntity<Object> updateUserPassword(
			@ApiParam(required = true, value = "send the AuthDTO object with username and password only.")
			@RequestBody AuthDTO authDTO) throws Exception {
		
		try {
			
			User user = this.service.findByUsername(authDTO.getUsername());
			if(user != null) {
				user.setPassword(passwordEncoder.encode(authDTO.getPassword()));
				user.setEnabled(false);
				user.setToken("");
				user.setDateExpire("");
				this.mongoTemplate.save(user);
				return ResponseEntity.status(HttpStatus.OK).body("\"Password updated...Retrieve token by accessing path '/recovery/token'");
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("User "+authDTO.getUsername()+" not found...");
			}
			
		}catch(Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}
	
	@ApiOperation(value = "Encrypt password only")
	@PostMapping(value = "/crypt/password")
	public ResponseEntity<Object> cryptPassword(@ApiParam(required = true, value = "type password only ..")
			@RequestBody AuthDTO authDTO) throws Exception {
		
		try {
			
	   		String password = service.encodePassword(authDTO.getPassword(), 3);
			return ResponseEntity.ok(password);
			
		}catch(Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}
	
	@ApiOperation(value = "Enter username to be removed from database")
	@DeleteMapping(value = "/remove/user")
	public ResponseEntity<Object> dropUser(@ApiParam(required = true, value = "Enter username ('username') only") @RequestBody AuthDTO authDTO)
			throws Exception {

		try {
			User user = this.service.findByUsername(authDTO.getUsername());
			if (user != null) {
				
				List<AuthorityUser> collection = this.mongoTemplate.findAllAndRemove(new Query(Criteria.where("user").is(user)), AuthorityUser.class);
				this.mongoTemplate.remove(user);

				return collection.size() > 0
					    ? ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY)
					        .body("User successfully removed... Total revoked rules: " + collection.size())
					    : ResponseEntity.status(HttpStatus.FORBIDDEN)
					        .body("User " + authDTO.getUsername() + " not found...");
			}
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(AuthDTO.builder().username(authDTO.getUsername()).status("User not found").build());
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
		}
	}
	
	private User createUserToken(User user, long days) throws Exception {

		try {
			return this.service.createUserToken(user, days);
		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	private AuthDTO mapUserToDTO(User user){
		
		AuthDTO authDTO = new AuthDTO();
		authDTO.setToken(user.getToken());
		authDTO.setExpire(user.getExpireAtDate());
		authDTO.setDateExpire(user.getDateExpire());
		authDTO.setDaysToExpire(user.getExpireAtDate());
		return authDTO;
	}
}
