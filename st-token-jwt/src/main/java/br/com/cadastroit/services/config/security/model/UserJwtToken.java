package br.com.cadastroit.services.config.security.model;

import java.io.Serializable;

import org.springframework.http.HttpStatus;

import br.com.cadastroit.services.config.security.JwtTokenUtil;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserJwtToken implements Serializable {

	private static final long serialVersionUID = -4627044374718392794L;

	private String user;
	private String group;
	private String token;
	private long expiration;
	private String dateExpire;
	private JwtTokenUtil jwtTokenUtil;
	private String message;
	private HttpStatus httpStatus;
	private int httpStatusCode;
}
