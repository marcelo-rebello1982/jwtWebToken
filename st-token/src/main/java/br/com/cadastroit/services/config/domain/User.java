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
import lombok.RequiredArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@RequiredArgsConstructor

@CompoundIndexes(value = {
        @CompoundIndex(name = "idx_uuid_user", def = "{'uuid':1}"),
        @CompoundIndex(name = "idx_username_user", def = "{'username':1}")
})
@Document(collection = "user")
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    private ObjectId id;

    @Indexed
    private UUID uuid;

    @Indexed(unique = true)
    private String username;
    private String password;
    private String token;
    private Long expireInDays;
    private String dateExpire;
    private Long expireAtDate;


    @Builder.Default
    private Boolean accountNonExpired = false;

    @Builder.Default
    private Boolean accountNonLocked = false;

    @Builder.Default
    private Boolean credentialNonExpired = false;

    @Builder.Default
    private Boolean enabled = false;
}
