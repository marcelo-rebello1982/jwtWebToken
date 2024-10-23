package br.com.cadastroit.services.repository;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;

import br.com.cadastroit.services.config.security.model.UserDetailsJwt;

public interface UserDetailJwtRepository extends MongoRepository<UserDetailsJwt, ObjectId> {}
