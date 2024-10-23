package br.com.cadastroit.services.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.cadastroit.services.config.domain.User;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.Builder;


@Builder
public class TokenRequestFilter extends OncePerRequestFilter {

    private MongoTemplate mongoTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final TokenCriteria tokenCriteria = TokenCriteria.builder().build();
        final String requestTokenHeader   = request.getHeader("Authorization");

        String username = null;
        String jwtToken = null;
        long expire		= System.currentTimeMillis();
        boolean processRequest = false;

     // JWT Token is in the form "Bearer token". Remove Bearer word and get only the Token
        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
            try {
                username  = tokenCriteria.getUsernameFromToken(jwtToken);
                User user = this.findUserByToken(jwtToken);
                if(user != null && user.getId() != null) {
                    if(user.getExpireAtDate() < expire) {
                        throw new ServletException("JWT Token has expired");
                    }else{
                        processRequest = true;
                    }
                }
            } catch (IllegalArgumentException e) {
                System.out.println("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {
                System.out.println("JWT Token has expired");
            }
        } else {
            logger.warn("JWT Token does not begin with Bearer String");
        }

        if (processRequest && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = TokenUserDetailsService.builder().mongoTemplate(this.mongoTemplate).build().loadUserByUsername(username);
            if (tokenCriteria.validateToken(jwtToken, userDetails)) {//if token is valid configure Spring Security to manually set authentication
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        chain.doFilter(request, response);
    }

    private User findUserByToken(String token) {
        User user = this.mongoTemplate.findOne(new Query(Criteria.where("token").is(token)), User.class);
        return user;
    }

}
