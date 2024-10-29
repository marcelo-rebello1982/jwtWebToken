package br.com.cadastroit.services.config.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import br.com.cadastroit.services.security.domain.Authority;
import br.com.cadastroit.services.security.domain.AuthorityUser;
import br.com.cadastroit.services.security.domain.User;
import br.com.cadastroit.services.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class NoSqlUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final MongoTemplate mongoTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Reading user by username...");
        User user = this.userRepository.findByUsername(username).orElseThrow(() -> {
            return new UsernameNotFoundException(String.format("Username %s not found", username));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                user.getPassword(),
                user.getEnabled(),
                user.getAccountNonExpired(),
                user.getCredentialNonExpired(),
                user.getAccountNonLocked(),
                convertToSpringAuthorities(this.mongoTemplate.find(new Query(Criteria.where("user").is(user)), AuthorityUser.class)));
    }

    private Collection<? extends GrantedAuthority> convertToSpringAuthorities(List<AuthorityUser> authorities) {
        if(authorities != null && authorities.size() > 0){
            return authorities.stream().map(AuthorityUser::getAuthority)
                    .collect(Collectors.toList())
                    .stream()
                    .map(Authority::getRole)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            
        } else return new ArrayList<>();

    }
}
