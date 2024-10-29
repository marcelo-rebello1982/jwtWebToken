package br.com.cadastroit.services.domain.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import br.com.cadastroit.services.domain.security.LoginFailure;
import br.com.cadastroit.services.security.domain.User;

@Repository
public interface LoginFailureRepository extends MongoRepository<LoginFailure, UUID> {
    List<LoginFailure> findAllByUserAndCreatedDateIsAfter(User user, long timestamp);
}
