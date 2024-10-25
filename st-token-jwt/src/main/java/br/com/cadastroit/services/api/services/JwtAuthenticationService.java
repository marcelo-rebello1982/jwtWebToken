package br.com.cadastroit.services.api.services;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

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
import br.com.cadastroit.services.utils.DateUtils;
import br.com.cadastroit.services.web.controllers.dto.JwtRequest;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class JwtAuthenticationService {
	
	private MongoTemplate mongoTemplate;
	
	private PasswordEncoder passwordEncoder;
	
	public final UserDetailJwtRepository userDetailJwtRepository;
	
	static final long EXPIRATION_TIME = System.getenv("expire") != null ? (Long.parseLong(System.getenv("EXPIRE")) * (1000 * 60 * 60 * 24))	: (1000 * 60 * 60 * 24);
	
	public UserDetailsJwt findNoSqlUser(Criteria criteria, JwtRequest jwtRequest) {
		
		UserDetailsJwt userDetailsJwt = this.mongoTemplate.findOne(new Query(criteria), UserDetailsJwt.class);
		return userDetailsJwt;
	}
	
	public UserDetailsJwt findNoSqlUser(Criteria criteria) {
		UserDetailsJwt userDetailsJwt = this.mongoTemplate.findOne(new Query(criteria), UserDetailsJwt.class);
		return userDetailsJwt;
	}
	
	public UserGroupJwt findUserGroup(JwtRequest jwtRequest) {
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
			
			Long dateToExpire =  this.calculateDateToExpire(jwtRequest.getDaysToExpire());

			final UserDetails userDetails = userDetailsService.loadUserByUsername(userDetailsJwt.getUsername());
			final String token 			  = jwtTokenUtil.generateToken(userDetails, dateToExpire);
			
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
			
			Long daysToExpire =  this.calculateDateToExpire(jwtRequest.getDaysToExpire());
			
			final UserDetails userDetails = userDetailsService.loadUserByUsername(userDetailsJwt.getUsername());
			final String token 			  = jwtTokenUtil.generateToken(userDetails, daysToExpire);
			
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
	
	
	public static long getDaysBetweenUtc(long startDate, long endDate, int addDays) {
		LocalDateTime date1 = LocalDateTime.ofInstant(Instant.ofEpochMilli(startDate), ZoneOffset.UTC);
		LocalDateTime date2 = LocalDateTime.ofInstant(Instant.ofEpochMilli(endDate), ZoneOffset.UTC);
		return ChronoUnit.DAYS.between(date1, date2);
	}

	public long addDaysUtc(long timestamp, long days) {

		return LocalDateTime.ofInstant(Instant.ofEpochMilli(timestamp), 
				ZoneOffset.UTC).plusDays(days)
					.toInstant(ZoneOffset.UTC)
						.toEpochMilli();
		
	}
	
	private long calculateDateToExpire(Long daysToExpire) {
		
		long days = Optional.ofNullable(DateUtils.getDaysBetweenUtc(
						DateUtils.getCurrentUtcTimestamp(), 
							this.calculateTokenValidity(daysToExpire)))
								.orElse(1L);
		return Instant.now()
					.plus(days * EXPIRATION_TIME, ChronoUnit.MILLIS)
						.toEpochMilli();
		
	}
	
	private long calculateTokenValidity (Long daysToExpire) {
		
		return new Date(System.currentTimeMillis() +
				( EXPIRATION_TIME * ( daysToExpire != null ?
						daysToExpire : 1L ))).getTime();
		
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
