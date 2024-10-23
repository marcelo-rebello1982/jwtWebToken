package br.com.cadastroit.services.config.repository;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import br.com.cadastroit.services.config.domain.Authority;

@Repository
public interface AuthorityRepository extends MongoRepository<Authority, ObjectId> {
}
