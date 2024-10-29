package br.com.cadastroit.services.domain.security;

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
@Document(collection = "login_success")
public class LoginSuccess {

    public static final long serialVersionUID = 1L;

    private UUID id;
    private User user;
    private String sourceIp;
    private long createdDate;
    private long lastModified;
    private String date;

}
