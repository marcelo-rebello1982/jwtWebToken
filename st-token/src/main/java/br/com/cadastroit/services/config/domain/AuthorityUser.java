package br.com.cadastroit.services.config.domain;

import java.io.Serializable;
import java.util.UUID;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@CompoundIndexes(value = {
        @CompoundIndex(name = "idx_user_authority_user", def = "{'user':1}"),
        @CompoundIndex(name = "idx_authority_authority_user", def = "{'authority':1}")
})
@Document(collection = "authority_user")
public class AuthorityUser implements Serializable {

    
	private static final long serialVersionUID = 1L;
	
	@Id
    private ObjectId id;
    private UUID uuid;

    @Indexed
    private User user;

    @Indexed
    private Authority authority;

}
