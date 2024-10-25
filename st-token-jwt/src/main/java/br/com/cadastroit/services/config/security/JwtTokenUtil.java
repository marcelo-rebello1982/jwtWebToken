package br.com.cadastroit.services.config.security;

import java.io.Serializable;
import java.text.DateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = -658909967540399384L;
	
	// EXPIRATION_TIME = 1 hour
	// sf-secret-acess-key-get-values-views 
	// Crypt 1 layer = Y3NmLXNlY3JldC1hY2Vzcy1rZXktZ2V0LXZhbHVlcy12aWV3cw==,
	// Crypt 2 layer = WTNObUxYTmxZM0psZEMxaFkyVnpjeTFyWlhrdFoyVjBMWFpoYkhWbGN5MTJhV1YzY3c9PQ==
	
	static final long EXPIRATION_TIME = (1000*60*60*24);
	static final String SECRET_KEY = System.getenv("SECRET_KEY") != null ? System.getenv("SECRET_KEY") : "imrDiAPcQAt1NfnWJj7P3IZR8glH1aQo0eSOseNlmZYWPWIx0Cye+EB7rJMfESicnHZx6c/WyEp4glBPOpimxQ==";
	static final String TOKEN_PREFIX 	= "Bearer";
	static final String HEADER_STRING 	= "Authorization";
	
	private long expiration 	= 0;
	private String dateExpire 	= "";


	
	public String getUsernameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}
	
	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}
	
	private Claims getAllClaimsFromToken(String token) {
		
		return Jwts.parser()
				.verifyWith(getSignKey())
					.build()
						.parseSignedClaims(token)
							.getPayload();
		
	}
	
	public String generateToken(UserDetails userDetails , long daysToExpire) {
		
		Map<String, Object> claims 	= new HashMap<>();
		Date expiration = new Date(daysToExpire);
		this.setExpiration(expiration.getTime());
		this.setDateExpire(DateFormat.getDateTimeInstance().format(expiration));
		return doGenerateToken(claims, userDetails.getUsername(), expiration);
		
	}

	// Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
	public String doGenerateToken(Map<String, Object> claims, String username, Date expiration) {

		return Jwts.builder()
				.claims().add(claims)
				.subject(username)
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(expiration)
				.and()
                .signWith(getSignKey())
				.compact();
	}
	
	private SecretKey getSignKey() {  
		byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	
	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}
	
	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

}
