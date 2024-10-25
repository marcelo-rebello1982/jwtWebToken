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

	private static final long serialVersionUID = 7179279592703941434L;
	
	private String token;
	private String jwttoken;
	private long expire;
	private String dateExpire;
	private String message;

}
