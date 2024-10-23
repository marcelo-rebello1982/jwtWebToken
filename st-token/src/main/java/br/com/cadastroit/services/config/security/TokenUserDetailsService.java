package br.com.cadastroit.services.config.security;

import java.util.ArrayList;
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

import br.com.cadastroit.services.config.domain.Authority;
import br.com.cadastroit.services.config.domain.AuthorityUser;
import br.com.cadastroit.services.config.domain.User;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Builder
@Data
public class TokenUserDetailsService implements UserDetailsService {

    private final MongoTemplate mongoTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Reading user by username...");
        Optional<User> user = Optional.ofNullable(this.mongoTemplate.findOne(new Query(Criteria.where("username").is(username)), User.class));
        if(!user.isPresent()){
            throw new UsernameNotFoundException(String.format("Username %s not found", username));
        }
        return new org.springframework.security.core.userdetails.User(user.get().getUsername(),
                user.get().getPassword(),
                user.get().getEnabled(),
                user.get().getAccountNonExpired(),
                user.get().getCredentialNonExpired(),
                user.get().getAccountNonLocked(),
                convertToSpringAuthorities(this.mongoTemplate.find(new Query(Criteria.where("user").is(user.get())), AuthorityUser.class)));
    }

    private Collection<? extends GrantedAuthority> convertToSpringAuthorities(List<AuthorityUser> authorities) {
        if(authorities != null && authorities.size() > 0){
            return authorities.stream().map(AuthorityUser::getAuthority)
                    .collect(Collectors.toList())
                    .stream()
                    .map(Authority::getRole)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }else{
            return new ArrayList<>();
        }
    }
}
