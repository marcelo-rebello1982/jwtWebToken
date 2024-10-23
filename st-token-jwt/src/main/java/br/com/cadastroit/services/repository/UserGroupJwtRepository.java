package br.com.cadastroit.services.repository;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;

import br.com.cadastroit.services.config.security.model.UserGroupJwt;

public interface UserGroupJwtRepository extends MongoRepository<UserGroupJwt, ObjectId> {}
