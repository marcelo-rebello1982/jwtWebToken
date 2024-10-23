package br.com.cadastroit.services.web.model;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthDTO implements Serializable {
	
    private static final long serialVersionUID = -978627970521298541L;
    
	private String username;
    private String password;
    private String token;
    private String role;
    private long expire;
    private String dateExpire;
    private long daysToExpire;
    private String status;

}
