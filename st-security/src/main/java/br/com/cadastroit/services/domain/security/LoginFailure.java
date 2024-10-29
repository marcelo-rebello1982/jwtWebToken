package br.com.cadastroit.services.domain.security;

import java.io.Serializable;
import java.util.UUID;

import org.springframework.data.mongodb.core.mapping.Document;

import br.com.cadastroit.services.security.domain.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Document(collection = "login_failure")
public class LoginFailure implements Serializable {

    public static final long serialVersionUID = 1L;

    private UUID id;
    private String username;
    private User user;
    private String sourceIp;
    private long createdDate;
    private long lastModified;
    private String date;

}
