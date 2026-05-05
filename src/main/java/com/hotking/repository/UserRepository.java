package com.hotking.repository;

import org.springframework.data.repository.CrudRepository;
import com.hotking.entity.User;

public interface UserRepository extends CrudRepository<User, Long> {

    User findByUsername(String username);
}
