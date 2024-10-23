package br.com.cadastroit.services.web.controllers.dto;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse implements Serializable {
	private static final long serialVersionUID = -8091879091924046844L;

	private String token;
	private String jwttoken;
	private long expire;
	private String dateExpire;

}
