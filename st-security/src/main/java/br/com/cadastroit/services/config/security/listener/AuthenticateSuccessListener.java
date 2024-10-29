package br.com.cadastroit.services.config.security.listener;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import br.com.cadastroit.services.domain.repository.LoginSuccessRepository;
import br.com.cadastroit.services.domain.security.LoginSuccess;
import br.com.cadastroit.services.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Component
public class AuthenticateSuccessListener {

    private final UserRepository userRepository;
    private final LoginSuccessRepository loginSuccessRepository;

    @EventListener
    public void listen(AuthenticationSuccessEvent event) {
        log.debug("Logged...");
        if (event.getSource() instanceof UsernamePasswordAuthenticationToken) {
            LoginSuccess.LoginSuccessBuilder builder = LoginSuccess.builder();

            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) event.getSource();
            if (token.getPrincipal() instanceof org.springframework.security.core.userdetails.User) {
                org.springframework.security.core.userdetails.User user = (User) token.getPrincipal();
                log.debug(String.format("User is logged %s", user.getUsername()));
                builder.user(this.userRepository.findByUsername(user.getUsername()).get());
            }
            if (token.getDetails() instanceof WebAuthenticationDetails) {
                WebAuthenticationDetails details = (WebAuthenticationDetails) token.getDetails();
                log.debug(String.format("Source IP: %s", details.getRemoteAddress()));
                builder.sourceIp(details.getRemoteAddress());
            }
            builder.createdDate(new Timestamp(event.getTimestamp()).getTime());
            builder.lastModified(new Timestamp(event.getTimestamp()).getTime());
            builder.id(UUID.randomUUID());

            LoginSuccess loginSuccess = builder.build();
            SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
            Date date = new Date(loginSuccess.getCreatedDate());
            String textDate = sdf.format(date);
            loginSuccess.setDate(textDate);

            loginSuccess = this.loginSuccessRepository.save(loginSuccess);
            log.debug(String.format("Login success saved. Id = %s", loginSuccess.getId()));
        }
    }
}
