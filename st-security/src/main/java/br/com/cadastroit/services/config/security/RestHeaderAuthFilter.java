package br.com.cadastroit.services.config.security;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.util.matcher.RequestMatcher;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RestHeaderAuthFilter extends AbstractRestAuthFilter {

    public RestHeaderAuthFilter(RequestMatcher requiresAuthRequestMatcher){
        super(requiresAuthRequestMatcher);
    }

    @Override
    protected String getPassword(HttpServletRequest request) {
        return request.getHeader("uuid");
    }

    @Override
    protected String getUsername(HttpServletRequest request) {
        return request.getHeader("key");
    }
}
