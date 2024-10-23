package br.com.cadastroit.services.api.services;

import java.util.Base64;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.cadastroit.services.config.security.model.UserDetailsJwt;
import br.com.cadastroit.services.config.security.model.UserGroupJwt;
import br.com.cadastroit.services.web.controllers.JwtAuthenticationController;
import br.com.cadastroit.services.web.controllers.dto.JwtRequest;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class JwtAuthenticationService {
	
	private MongoTemplate mongoTemplate;
	
	private PasswordEncoder passwordEncoder;

	public UserDetailsJwt findNoSqlUser(JwtAuthenticationController jwtAuthenticationController, Criteria criteria, JwtRequest jwtRequest) {
		UserDetailsJwt userDetailsJwt = jwtAuthenticationController.mongoTemplate.findOne(new Query(criteria), UserDetailsJwt.class);
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

	public String createUserToken(JwtAuthenticationController jwtAuthenticationController, UserDetailsJwt userDetailsJwt, JwtRequest jwtRequest) throws Exception{
		try {
			
			jwtAuthenticationController.jwtUserDetailsService().setUser(userDetailsJwt.getUsername());
			jwtAuthenticationController.jwtUserDetailsService().setPassword(userDetailsJwt.getPassword());
			jwtAuthenticationController.jwtUserDetailsService().setTextPlainPass(jwtRequest.getPassword());
		
			final UserDetails userDetails = jwtAuthenticationController.jwtUserDetailsService().loadUserByUsername(userDetailsJwt.getUsername());
			final String token 			  = jwtAuthenticationController.jwtTokenUtil().generateToken(userDetails);
			
			userDetailsJwt.setJwttoken(token);
			userDetailsJwt.setDateExpire(jwtAuthenticationController.jwtTokenUtil().getDateExpire());
			userDetailsJwt.setExpire(jwtAuthenticationController.jwtTokenUtil().getExpiration());
			
			jwtAuthenticationController.userDetailJwtRepository.save(userDetailsJwt);
			return token;
		} catch (Exception e) {
			throw new Exception (e);
		}
	}
	
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

}
