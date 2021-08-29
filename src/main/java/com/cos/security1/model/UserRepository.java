package com.cos.security1.model;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer>{
	//findBy규칙 ->Username문법
	//select *form user where username =1?
	//위커리가 작동한다.
	//findByUsername 같은 것을 jpaQueryMethods라고 한다.
	//검색하면 나온다.
	public User findByUsername(String username);
}
