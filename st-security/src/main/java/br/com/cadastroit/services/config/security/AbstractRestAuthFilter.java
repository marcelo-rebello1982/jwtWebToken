package br.com.cadastroit.services.config.security;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.function.Function;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.header.Header;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.cadastroit.services.security.domain.AccountCredentials;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class AbstractRestAuthFilter extends OncePerRequestFilter {

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	private UserDetailsService userDetailsService;

	public static final long ACCESS_TOKEN_VALIDITY_SECONDS = 5 * 60 * 60;
	public static final String SIGNING_KEY = "devglan123r";
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING = "Authorization";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		// Get JWT token from HTTP request
		String token = getTokenFromRequest(request);

		// Validate Token
		if (StringUtils.isNoneEmpty(token) && jwtTokenProvider.validateToken(token)) {
			// get username from token
			String username = jwtTokenProvider.getUsername(token);

			UserDetails userDetails = userDetailsService.loadUserByUsername(username);

			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null,
					userDetails.getAuthorities());

			authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

			SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		}

		filterChain.doFilter(request, response);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
			throws IOException, ServletException {

		SecurityContextHolder.clearContext();
		if (log.isDebugEnabled()) {
			this.log.trace("Failed to process authentication request", failed);
			this.log.trace("Cleared SecurityContextHolder");
			this.log.trace("Handling authentication failure");
		}
		response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
			throws IOException, ServletException {

		if (this.log.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
		}
		SecurityContext context = SecurityContextHolder.getContext();
		context.setAuthentication(authResult);
		SecurityContextHolder.setContext(context);
	}

	public Authentication attemptAuthentication11(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		String username = getUsername(request);
		String password = getPassword(request);

		if (username == null)
			username = "";
		if (password == null)
			password = "";

		log.debug("Authenticating user: " + username);

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
		if (StringUtils.isNotEmpty(username)) {
			return this.getAuthenticationManager().authenticate(token);
		} else {
			return null;
		}
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
			throws AuthenticationException, IOException, ServletException {

		AccountCredentials creds = new ObjectMapper().readValue(req.getInputStream(), AccountCredentials.class);

		return getAuthenticationManager()
				.authenticate(new UsernamePasswordAuthenticationToken(creds.getUsername(), creds.getPassword(), Collections.emptyList()));
	}

	private String recoverToken(HttpServletRequest request) {

		var authorizationHeader = request.getHeader("Authorization");
		if (authorizationHeader != null) {
			return authorizationHeader.replace("Bearer ", "");
		}

		return null;
	}

	public Boolean validateToken(String token, UserDetailsService userDetails) {

		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	public String getUsernameFromToken(String token) {

		return getClaimFromToken(token, Claims::getSubject);
	}

	private Boolean isTokenExpired(String token) {

		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	public Date getExpirationDateFromToken(String token) {

		return getClaimFromToken(token, Claims::getExpiration);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {

		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) {

		return Jwts.parser().setSigningKey(SIGNING_KEY).parseClaimsJws(token).getBody();
	}
	
    private String getTokenFromRequest(HttpServletRequest request){
    	
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(StringUtils.isNoneEmpty(bearerToken) && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7, bearerToken.length());
        }

        return null;
    }

	protected abstract String getPassword(HttpServletRequest request);

	protected abstract String getUsername(HttpServletRequest request);

}
