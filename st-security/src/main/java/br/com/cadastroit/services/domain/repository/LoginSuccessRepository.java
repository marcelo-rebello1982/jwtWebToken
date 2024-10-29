package br.com.cadastroit.services.domain.repository;

import java.util.UUID;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import br.com.cadastroit.services.domain.security.LoginSuccess;

@Repository
public interface LoginSuccessRepository extends MongoRepository<LoginSuccess, UUID> { }
