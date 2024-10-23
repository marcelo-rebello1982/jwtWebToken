package br.com.cadastroit.services.config.security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.context.annotation.Bean;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthorityUser {

    private UserGroupJwt authority;
    private UserDetailsJwt user;
}
