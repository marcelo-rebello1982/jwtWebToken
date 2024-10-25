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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.cadastroit.services.config.security.model.UserDetailsJwt;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

@Builder
@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {
	
	private MongoTemplate mongoTemplate;
	private PasswordEncoder passwordEncoder;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException, IllegalArgumentException, ExpiredJwtException {
		
		final String requestTokenHeader = request.getHeader("Authorization");

		JwtTokenUtil jwtTokenUtil = JwtTokenUtil.builder().build();
		JwtUserDetailsService userDetailsService = JwtUserDetailsService.builder().mongoTemplate(this.mongoTemplate).encoder(this.passwordEncoder).build();

		String username 		  = null;
		String jwtToken 		  = null;
		boolean processRequest 	  = false;
		
		if (validadeAuthHeader(requestTokenHeader)) { 
			jwtToken = requestTokenHeader.substring(7);
			
			try {
				
				username = jwtTokenUtil.getUsernameFromToken(jwtToken); // remove Bearer from token
				Criteria criteria = Criteria.where("jwttoken").is(jwtToken);
				UserDetailsJwt userDetailsJwt = this.findNoSqlUser(criteria);
				
				if(validateUserDetails(userDetailsJwt)) {
					if(validadeDateToken(userDetailsJwt)) {
						
						try {
							setupUserDetailServiceValidToken(userDetailsJwt, userDetailsService);
							processRequest = true;
						}catch(Exception ex) {
							throw new ServletException(ex.getMessage());
						} 
						
					} else throw new ServletException("JWT Token has expired");
				}
				
			} catch (IllegalArgumentException e) {
				throw new IllegalArgumentException("Erro na captacao do token. Verifique se o token foi declarado corretamente.");
			} catch (ExpiredJwtException e) {
				throw new ExpiredJwtException(null, null, "Token expirou. Renove ou atualize seu token.");
			}
		} else {
			logger.warn("Token fora do formato. Verifique se o termo Bearer foi inserido na chamada.");
		}

		// Once we get the token validate it.
		if (processRequest && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {//if token is valid configure Spring Security to manually set authentication
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());				
				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				// After setting the Authentication in the context, we specify that the current user is authenticated. So it passes the Spring Security Configurations successfully.
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		chain.doFilter(request, response);
	}

	private boolean validadeAuthHeader(final String authHeader) {
		return authHeader != null && authHeader.startsWith("Bearer ");
	}

	private boolean validadeDateToken(UserDetailsJwt userDetailsJwt) {
		
		long expire = System.currentTimeMillis();
		return userDetailsJwt.getExpire() > expire;
	}

	private boolean validateUserDetails(UserDetailsJwt userDetailsJwt) {
		return userDetailsJwt != null && userDetailsJwt.get_id() != null;
	}
	
	private UserDetailsJwt findNoSqlUser(Criteria criteria) {
		UserDetailsJwt userDetailsJwt = this.mongoTemplate.findOne(new Query(criteria), UserDetailsJwt.class);
		return userDetailsJwt;
	}
	
	private void setupUserDetailServiceValidToken(UserDetailsJwt userDetailsJwt, JwtUserDetailsService userDetailsService) throws Exception{
		try {
			userDetailsService.setUser(userDetailsJwt.getUsername());
			userDetailsService.setPassword(userDetailsJwt.getPassword());
		} catch (Exception e) {
			throw new Exception (e);
		}
	}
}
