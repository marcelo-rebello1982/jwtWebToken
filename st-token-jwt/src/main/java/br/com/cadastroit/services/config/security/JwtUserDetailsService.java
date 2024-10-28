package br.com.cadastroit.services.config.security;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import br.com.cadastroit.services.config.security.model.AuthorityUser;
import br.com.cadastroit.services.config.security.model.UserDetailsJwt;
import br.com.cadastroit.services.config.security.model.UserGroupJwt;
import br.com.cadastroit.services.utils.BigDecimalUtils;
import br.com.cadastroit.services.utils.DateUtils;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Data
@Builder
@Slf4j
public class JwtUserDetailsService implements UserDetailsService{
	
	private String user;
	private String password;
	private String textPlainPass;

	private PasswordEncoder encoder;
	private MongoTemplate mongoTemplate;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		log.debug("Reading user by username...");
		Optional<UserDetailsJwt> user = Optional.ofNullable(this.mongoTemplate.findOne(new Query(Criteria.where("username").is(username)), UserDetailsJwt.class));
		if(!user.isPresent()){
			throw new UsernameNotFoundException(String.format("Credentials are invalid or not found", username));
		}
		return new org.springframework.security.core.userdetails.User(user.get().getUsername(),
				user.get().getPassword(),
				user.get().isEnabled(),
				user.get().isAccountNonExpired(),
				user.get().isCredentialNonExpired(),
				user.get().isAccountNonLocked(),
				convertToSpringAuthorities(this.mongoTemplate.find(new Query(Criteria.where("user").is(user.get())), AuthorityUser.class)));
	}

	private Collection<? extends GrantedAuthority> convertToSpringAuthorities(List<AuthorityUser> authorities) {
		if(authorities != null && authorities.size() > 0){
			return authorities.stream().map(AuthorityUser::getAuthority)
					.collect(Collectors.toList())
					.stream()
					.map(UserGroupJwt::getGroup)
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toList());
		} else return new ArrayList<>();
		
	}
	
	public boolean validateUserDetails(UserDetailsJwt userDetailsJwt) {
		return userDetailsJwt != null && userDetailsJwt.get_id() != null;
	}
	
	public boolean dateTokenIsValid(UserDetailsJwt userDetailsJwt) {
		
		long dateToExpire = userDetailsJwt.getExpire(); 
		long actualDate = System.currentTimeMillis();
		
		 // caso igual a zero, a validade do token 
		 // é a mesma ou anterior a data atual,
		 // portando esta expirado.
		BigDecimal returnZeroIfExpiretad =  BigDecimalUtils.zeroIfNegative(DateUtils.calculateDaysBetWeen_(
											new Calendar.Builder()
												.setInstant(actualDate)
													.build(), 
											new Calendar.Builder()
												.setInstant(dateToExpire)
													.build(),
														true));
		
		return returnZeroIfExpiretad.intValue() == 0 ? false : true;
		
	}
	
}
