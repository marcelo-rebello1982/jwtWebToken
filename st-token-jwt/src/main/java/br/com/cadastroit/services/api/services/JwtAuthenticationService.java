package br.com.cadastroit.services.api.services;

import java.util.Base64;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.cadastroit.services.config.security.JwtTokenUtil;
import br.com.cadastroit.services.config.security.JwtUserDetailsService;
import br.com.cadastroit.services.config.security.model.UserDetailsJwt;
import br.com.cadastroit.services.config.security.model.UserGroupJwt;
import br.com.cadastroit.services.config.security.model.UserJwtToken;
import br.com.cadastroit.services.repository.UserDetailJwtRepository;
import br.com.cadastroit.services.web.controllers.JwtAuthenticationController;
import br.com.cadastroit.services.web.controllers.dto.JwtRequest;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class JwtAuthenticationService {
	
	private MongoTemplate mongoTemplate;
	
	private PasswordEncoder passwordEncoder;
	
	public final UserDetailJwtRepository userDetailJwtRepository;
	
	public UserDetailsJwt findNoSqlUser(Criteria criteria, JwtRequest jwtRequest) {
		
		UserDetailsJwt userDetailsJwt = this.mongoTemplate.findOne(new Query(criteria), UserDetailsJwt.class);
		return userDetailsJwt;
	}
	
	public UserDetailsJwt findNoSqlUser(JwtAuthenticationController jwtAuthenticationController, Criteria criteria, JwtRequest jwtRequest) {
		UserDetailsJwt userDetailsJwt = this.mongoTemplate.findOne(new Query(criteria), UserDetailsJwt.class);
		return userDetailsJwt;
	}
	
	public UserGroupJwt returnUserGroup(JwtRequest jwtRequest) {
		UserGroupJwt userGroupJwt = this.mongoTemplate.findOne(new Query(Criteria.where("group").is(jwtRequest.getGroup().toLowerCase())),UserGroupJwt.class);
		return userGroupJwt;
	}
	
	public UserDetailsJwt buildJwtUserDetais(UserGroupJwt userGroupJwt, JwtRequest jwtRequest) {

		UserDetailsJwt userDetailsJwtCreate = new UserDetailsJwt();
		userDetailsJwtCreate.setUsername(jwtRequest.getUsername());
		userDetailsJwtCreate.setPassword(passwordEncoder.encode(jwtRequest.getPassword()));
		userDetailsJwtCreate.setUserGroupJwt(userGroupJwt);
		
		return userDetailsJwtCreate;
		
	}

	public String[] createUserTokenStr(UserDetailsJwt userDetailsJwt, JwtRequest jwtRequest) throws Exception{
		try {
			
			
			JwtTokenUtil jwtTokenUtil = this.createJwtTokenUtil();
			JwtUserDetailsService userDetailsService = this.createJwtUserDetailsService();
			
			userDetailsService.setUser(userDetailsJwt.getUsername());
			userDetailsService.setPassword(userDetailsJwt.getPassword());
			userDetailsService.setTextPlainPass(jwtRequest.getPassword());
			
			final UserDetails userDetails = userDetailsService.loadUserByUsername(userDetailsJwt.getUsername());
			final String token 			  = jwtTokenUtil.generateToken(userDetails);
			
			userDetailsJwt.setJwttoken(token);
			userDetailsJwt.setDateExpire(jwtTokenUtil.getDateExpire());
			userDetailsJwt.setExpire(jwtTokenUtil.getExpiration());
			
			this.userDetailJwtRepository.save(userDetailsJwt);
			
			String[] response = new String[3];

			response[0] = token;
			response[1] = String.valueOf(jwtTokenUtil.getExpiration());
			response[2] = jwtTokenUtil.getDateExpire();
			
			return response;
		} catch (Exception e) {
			throw new Exception (e);
		}
	}
	
	public UserJwtToken createUserToken(UserDetailsJwt userDetailsJwt, JwtRequest jwtRequest) throws Exception{
		
		try {
			
			JwtTokenUtil jwtTokenUtil = this.createJwtTokenUtil();
			JwtUserDetailsService userDetailsService = this.createJwtUserDetailsService();
			
			userDetailsService.setUser(userDetailsJwt.getUsername());
			userDetailsService.setPassword(userDetailsJwt.getPassword());
			userDetailsService.setTextPlainPass(jwtRequest.getPassword());
			
			final UserDetails userDetails = userDetailsService.loadUserByUsername(userDetailsJwt.getUsername());
			final String token 			  = jwtTokenUtil.generateToken(userDetails);
			
			userDetailsJwt.setJwttoken(token);
			userDetailsJwt.setDateExpire(jwtTokenUtil.getDateExpire());
			userDetailsJwt.setExpire(jwtTokenUtil.getExpiration());
			
			this.userDetailJwtRepository.save(userDetailsJwt);
			
			UserJwtToken userTokenJwt = UserJwtToken.builder()
					.token(token)
					.expiration(userDetailsJwt.getExpire())
					.dateExpire(userDetailsJwt.getDateExpire())
					.jwtTokenUtil(jwtTokenUtil)
					.build();
			
			return userTokenJwt;
			
		} catch (Exception e) {
			throw new Exception (e);
		}
	}

	// use to crypt ou decrypt password 
	public String processPassword(JwtRequest jwtRequest) {
	    return jwtRequest.isCrypt()
	        ? encodePassword(jwtRequest.getPassword(), 3)
	        : decodePassword(jwtRequest.getPassword(), 3);
	}
	
	public String encodePassword(String password, int times) {

		 return times == 0 
			        ? password 
			        : encodePassword(Base64.getEncoder()
			        		.encodeToString(password.getBytes()), times - 1);
	}
	
	public String decodePassword(String password, int times) {
		
       return times == 0
       		? password
       		: decodePassword(new String(Base64.getDecoder()
       				.decode(password)), times - 1);
	}
	
	public JwtTokenUtil createJwtTokenUtil() {

		JwtTokenUtil jwtTokenUtil = null;

		if (jwtTokenUtil == null) {
			jwtTokenUtil = JwtTokenUtil.builder().build();
		}

		return jwtTokenUtil;

	}

	public JwtUserDetailsService createJwtUserDetailsService() {

		JwtUserDetailsService userDetailsService = null;

		if (userDetailsService == null) {
			userDetailsService = JwtUserDetailsService.builder().mongoTemplate(this.mongoTemplate).encoder(this.passwordEncoder).build();
		}

		return userDetailsService;
	}
}
