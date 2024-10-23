package br.com.cadastroit.services.web.controllers.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JwtRequest implements Serializable {
	
	private static final long serialVersionUID = 2419409605400187008L;
	private String username;
    private String password;
    private String token;
    private String group;
    private boolean crypt;

}
