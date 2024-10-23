package br.com.cadastroit.services.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import br.com.cadastroit.services.config.domain.User;

import java.io.Serializable;
import java.text.DateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

@Builder
@Data
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = -6586911795436612150L;

	// EXPIRATION_TIME = 1 hour
	// csf-secret-acess-key-get-values-views 
	// Crypt 1 layer = Y3NmLXNlY3JldC1hY2Vzcy1rZXktZ2V0LXZhbHVlcy12aWV3cw==,
	// Crypt 2 layer = WTNObUxYTmxZM0psZEMxaFkyVnpjeTFyWlhrdFoyVjBMWFpoYkhWbGN5MTJhV1YzY3c9PQ==
	static final long EXPIRATION_TIME = (1000*60*60*24);
	static final String SECRET_KEY = System.getenv("SECRET_KEY") != null ? System.getenv("SECRET_KEY") : "imrDiAPcQAt1NfnWJj7P3IZR8glH1aQo0eSOseNlmZYWPWIx0Cye+EB7rJMfESicnHZx6c/WyEp4glBPOpimxQ==";
	static final String SECRET = System.getenv("SECRET") != null ? System.getenv("SECRET") : "WTNObUxYTmxZM0psZEMxaFkyVnpjeTFyWlhrdFoyVjBMWFpoYkhWbGN5MTJhV1YzY3c9PQ==";
	static final String TOKEN_PREFIX 	= "Bearer";
	static final String HEADER_STRING 	= "Authorization";
	
	private long expiration 	= 0;
	private String dateExpire 	= "";
	
	public String getUsernameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().verifyWith(
				getSignKey())
					.build()
						.parseSignedClaims(token)
							.getPayload();
		
	}
	
	private SecretKey getSignKey() {  
		byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims 	= new HashMap<>();
		Date expiration 			= new Date(System.currentTimeMillis()+EXPIRATION_TIME);
		this.setExpiration(expiration.getTime());
		this.setDateExpire(DateFormat.getDateTimeInstance().format(expiration));
		return doGenerateToken(claims, userDetails.getUsername(), expiration);
	}

	// while creating the token -
	// 1. Define claims of the token, like Issuer, Expiration, Subject, and the ID
	// 2. Sign the JWT using the HS512 algorithm and secret key.
	// 3. According to JWS Compact
	// Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
	// compaction of the JWT to a URL-safe string
	public String doGenerateToken(Map<String, Object> claims, String subject, Date expiration) {

		return Jwts.builder()
				.claims().add(claims)
				.subject(subject)
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(expiration)
				.and()
                .signWith(getSignKey())
				.compact();
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
}
