package br.com.cadastroit.services.config.security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.io.Serializable;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Document(collection = "user_detail_jwt")
public class UserDetailsJwt implements Serializable {

	private static final long serialVersionUID = 1l;

	@Id
	private ObjectId _id;
	
	private String username;
	private String password;
	private String jwttoken;
	private Long expire;
	private String dateExpire;

	@Builder.Default
	private boolean enabled = true;

	@Builder.Default
	private boolean accountNonExpired = true;

	@Builder.Default
	private boolean credentialNonExpired = true;

	@Builder.Default
	private boolean accountNonLocked = true;
	
	@DBRef
	private UserGroupJwt userGroupJwt;
}
