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
@AllArgsConstructor
@NoArgsConstructor
@CompoundIndexes(value = {
        @CompoundIndex(name = "idx_uuid_authority", def = "{'uuid':1}"),
        @CompoundIndex(name = "idx_role_authority", def = "{'role':1}")
})
@Document(collection = "authority")
public class Authority implements Serializable {

    private static final long serialVersionUID = 1L;

	@Id
    private ObjectId id;
    private UUID uuid;

    @Indexed
    private String role;

}
