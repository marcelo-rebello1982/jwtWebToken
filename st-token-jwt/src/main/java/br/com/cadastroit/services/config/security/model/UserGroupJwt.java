package br.com.cadastroit.services.config.security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.io.Serializable;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Document(collection = "user_group_jwt")
public class UserGroupJwt implements Serializable {

	private static long serialVersionUID = 1l;

	@Id
	private ObjectId _id;
	private String group;

}
