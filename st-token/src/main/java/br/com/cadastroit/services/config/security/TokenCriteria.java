package br.com.cadastroit.services.config.security;

import java.io.Serializable;
import java.security.Key;
import java.text.DateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;

import br.com.cadastroit.services.config.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenCriteria implements Serializable {

	private static final long serialVersionUID = -6586911795436612150L;

	// Expire = 1 hour
	// Key = st-token-secret-20XX
	// Hash = $2y$24$Gy87Sjhg2be8dTU2anBWmu98W5UE0tmV0F6K365wK/ZHfu.W7Jdey
	
	static final long EXPIRATION_TIME = System.getenv("expire") != null ? (Long.parseLong(System.getenv("EXPIRE")) * (1000 * 60 * 60 * 24))	: (1000 * 60 * 60 * 24);
	static final String SECRET = System.getenv("SECRET_KEY") != null ? System.getenv("SECRET_KEY") : "JDJ5JDI0JEd5ODdTamhnMmJlOGRUVTJhbkJXbXU5OFc1VUUwdG1WMEY2SzM2NXdLL1pIZnUuVzdKZGV5";
	static final String SECRET_KEY = System.getenv("SECRET_KEY") != null ? System.getenv("SECRET_KEY") : "imrDiAPcQAt1NfnWJj7P3IZR8glH1aQo0eSOseNlmZYWPWIx0Cye+EB7rJMfESicnHZx6c/WyEp4glBPOpimxQ==";
	static final String TOKEN_PREFIX = "Bearer";
	static final String HEADER_STRING = "Authorization";

	@Builder.Default
	private long expiration = 0;

	@Builder.Default
	private String dateExpire = "";

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
	
	public String generateToken(User user) {

		Map<String, Object> claims = new HashMap<>();
		Date expiration = new Date(System.currentTimeMillis() + EXPIRATION_TIME);
		this.setExpiration(expiration.getTime());
		this.setDateExpire(DateFormat.getDateTimeInstance().format(expiration));
		return doGenerateToken(claims, user, expiration);
	}

	// while creating the token -
	// 1. Define claims of the token, like Issuer, Expiration, Subject, and the ID
	// 2. Sign the JWT using the HS512 algorithm and secret key.
	// 3. According to JWS Compact
	// Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
	// compaction of the JWT to a URL-safe string
	public String doGenerateToken(Map<String, Object> claims, User user, Date expiration) {

		return Jwts.builder()
				.claims().add(claims)
				.subject(user.getUsername())
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
	
	private Key getSignKeyNotUsed() {
		return SIG.HS256.key().build();
	} 
	
	public String extractUser(String token) {

		Claims claims = Jwts.parser()
				.verifyWith(getSignKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
		
		return claims.getSubject();
	}
	

	   
	public Boolean validateToken(String token, UserDetails userDetails) {

		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	
	private Boolean isTokenExpired(String token) {

		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	public static String getSecretKeyAsString(Key SECRET_KEY) {

		return Base64.getEncoder().encodeToString(SECRET_KEY.getEncoded());
	}
}
