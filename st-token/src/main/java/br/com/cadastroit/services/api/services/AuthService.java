package br.com.cadastroit.services.api.services;

import java.text.DateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;

import br.com.cadastroit.services.config.domain.User;
import br.com.cadastroit.services.config.security.TokenCriteria;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class AuthService {
	
	private MongoTemplate mongoTemplate;

	public User createUserToken(User user, long days) throws Exception{
		try {
			TokenCriteria tokenCriteria = TokenCriteria.builder().build();
			user = this.findByUsername(user.getUsername());
			if(user != null) {
				
				final String token = tokenCriteria.generateToken(user);
				user.setToken(token);
				user.setDateExpire(tokenCriteria.getDateExpire());
				user.setExpireInDays(tokenCriteria.getExpiration());
				user.setEnabled(true);
				user = this.mongoTemplate.save(user);
				
				return user;
			}else{
				throw new Exception(String.format("invalid credentials..."));
			}
		} catch (Exception e) {
			throw new Exception (e);
		}
	}
	
	private long updateTokenValidity(int days) {

		long EXPIRATION_TIME = System.currentTimeMillis() + ((1000 * 60 * 60 * 24) * days);
		long dateExpiration = new Date(System.currentTimeMillis() + EXPIRATION_TIME).getTime();
		return dateExpiration;

	}
	
	public String encodePassword(String password, int times) {

		 return times == 0 
			        ? password 
			        : encodePassword(Base64.getEncoder()
			        		.encodeToString(password.getBytes()), times - 1);
	}
	
	public long calculateDaysToExpire(Long daysToExpire) {
		return System.currentTimeMillis() + ( daysToExpire * (1000 * 60 * 60 * 24));
	}
	
	public String calculateDaysToExpire(Date expiration) {
		return DateFormat.getDateTimeInstance().format(expiration);
	}
	
	public User findByUsername(String username) {
		Optional<User> user = Optional.ofNullable(this.mongoTemplate.findOne(new Query(Criteria.where("username").is(username)), User.class));
		if(user.isPresent()) {
			return user.get();
		}
		return null;
	}
	
	public User findByUsername(String username, String password) {
		Optional<User> user = Optional.ofNullable(this.mongoTemplate.findOne(new Query(Criteria.where("username").is(username)
																					.and("password").is(password)), User.class));
		
		if(user.isPresent()) {
			return user.get();
		}
		return null;
	}

	public User findByToken(String token) {
		Optional<User> user = Optional.ofNullable(this.mongoTemplate.findOne(new Query(Criteria.where("token").is(token)), User.class));
		if(user.isPresent()) {
			return user.get();
		}
		return null;
	}
}
