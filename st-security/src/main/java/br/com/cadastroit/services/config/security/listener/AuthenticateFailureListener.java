package br.com.cadastroit.services.config.security.listener;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import br.com.cadastroit.services.domain.repository.LoginFailureRepository;
import br.com.cadastroit.services.domain.security.LoginFailure;
import br.com.cadastroit.services.security.domain.User;
import br.com.cadastroit.services.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Component
public class AuthenticateFailureListener {

    private final LoginFailureRepository loginFailureRepository;
    private final UserRepository userRepository;

    @EventListener
    public void listen(AuthenticationFailureBadCredentialsEvent event) {
        log.debug("Login Failure...");
        if(event.getSource() instanceof UsernamePasswordAuthenticationToken) {
            LoginFailure.LoginFailureBuilder builder = LoginFailure.builder();
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) event.getSource();
            log.debug(String.format("Failed on authentication. User = %s", token.getPrincipal()));

            builder.username(token.getPrincipal().toString());
            Optional<User> user = this.userRepository.findByUsername(token.getPrincipal().toString());
            if(user.isPresent()){
                builder.user(user.get());
            }
            if (token.getDetails() instanceof WebAuthenticationDetails) {
                WebAuthenticationDetails details = (WebAuthenticationDetails) token.getDetails();
                log.debug(String.format("Source IP: %s", details.getRemoteAddress()));
                builder.sourceIp(details.getRemoteAddress());
            }
            builder.createdDate(new Timestamp(System.currentTimeMillis()).getTime());
            builder.lastModified(new Timestamp(System.currentTimeMillis()).getTime());
            builder.id(UUID.randomUUID());

            LoginFailure loginFailure = builder.build();
            SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
            Date date = new Date(loginFailure.getCreatedDate());
            String textDate = sdf.format(date);
            loginFailure.setDate(textDate);
            loginFailure = this.loginFailureRepository.save(loginFailure);

            log.debug(String.format("Login failed has saved, id = %s", loginFailure.getId()));
            if(loginFailure.getUser() != null){
                lockUserAccount(loginFailure.getUser());
            }
        }
    }

    private void lockUserAccount(User user) {
        Long failuresCount = System.getenv("failures_count") == null ? Long.parseLong(System.getenv("failures_count")) : 10;
        List<LoginFailure> failures = this.loginFailureRepository.findAllByUserAndCreatedDateIsAfter(user, Timestamp.valueOf(LocalDateTime.now().minusDays(1)).getTime());
        if(failures.size() > failuresCount.longValue()){
            log.debug("Locking user account...");
            user.setAccountNonLocked(false);
            this.userRepository.save(user);
        }
    }
}
