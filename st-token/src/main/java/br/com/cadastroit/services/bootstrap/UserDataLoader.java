package br.com.cadastroit.services.bootstrap;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import br.com.cadastroit.services.config.domain.Authority;
import br.com.cadastroit.services.config.domain.AuthorityUser;
import br.com.cadastroit.services.config.domain.User;
import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class UserDataLoader {

    private final String PASSWORD = "$2y$12$vuSRMB4Tf8zLuXo.Gfx5WeNP0kmYlQ5zNS1O0rIoxR.h3CyMRswoi";
    private MongoTemplate mongoTemplate;
    private PasswordEncoder encoder;

    private Authority findByRole(String role){
        Optional<Authority> authority = Optional.ofNullable(mongoTemplate.findOne(new Query(Criteria.where("role").is(role)),Authority.class));
        if(authority.isPresent()){
            return authority.get();
        }
        return null;
    }
    private User findByUseranme(String username){
        Optional<User> user = Optional.ofNullable(mongoTemplate.findOne(new Query(Criteria.where("username").is(username)),User.class));
        if(user.isPresent()){
            return user.get();
        }
        return null;
    }

    private AuthorityUser findUserRole(User user, Authority authority){
        Optional<AuthorityUser> authorityUser = Optional.ofNullable(mongoTemplate.findOne(new Query(Criteria.where("user").is(user).and("authority").is(authority)),AuthorityUser.class));
        if(authorityUser.isPresent()){
            return authorityUser.get();
        }
        return null;
    }

    public void createRoles() throws Exception {
        List<String> roles = Stream.of("ROLE_ADMIN", "ROLE_USER", "ROLE_CUSTOMER").collect(Collectors.toList());
        AtomicReference<String> username = new AtomicReference<>("st-admin-20xx#1");
        User user = this.findByUseranme(username.get());
        AtomicReference<User> atUser = new AtomicReference<>(null);
        if(user != null){
            atUser.set(user);
        }
        roles.forEach(role -> {
            Authority authority = this.findByRole(role);
            if(authority == null){
                authority = Authority.builder().role(role).uuid(UUID.randomUUID()).build();
                authority = this.mongoTemplate.save(authority);
            }

            User u = atUser.get();
            if(u == null){
            	String tmp = encoder.encode(PASSWORD);
                u = User.builder().uuid(UUID.randomUUID()).username(username.get()).password(encoder.encode(PASSWORD))
                        .enabled(true).accountNonExpired(true).accountNonLocked(true).credentialNonExpired(true).build();
                u = this.mongoTemplate.save(u);
                atUser.set(u);
            }

            AuthorityUser authorityUser = findUserRole(u, authority);
            if(authorityUser == null){
                authorityUser = AuthorityUser.builder().user(u).authority(authority).uuid(UUID.randomUUID()).build();
                this.mongoTemplate.save(authorityUser);
            }
        });
    }
}
