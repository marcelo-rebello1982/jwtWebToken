package br.com.cadastroit.services.config.security.model;

import java.io.Serializable;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Document(collection = "user_group_jwt")
public class UserGroupJwt implements Serializable {

	private static final long serialVersionUID = -8125795803710644815L;
	
	@Id
	private ObjectId _id;
	private String group;

}
