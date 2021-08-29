package com.cos.security1.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.security1.model.User;
import com.cos.security1.model.UserRepository;
//@Service사용해서 메모리에 띄운다.
//@Service가 언제 발동을하냐면
//시큐리티 설정에서 .loginProcessingUrl("/login")을 걸어놨기때문에
//   /login요청이 오면 자동으로 UserDetailsService 타입으로 IOC되어 있는 loadUserByUsername함수가 실행
//위 내용은 규칙이기 때문에 꼭 이렇게 해야만하는것이다.

@Service
public class PrincipalDetailsService implements UserDetailsService{

	@Autowired
	private UserRepository userRepository;
	
	//이함수의 return이 어느쪽으로 되냐면
	//UserDetails함수가 리턴이 되면 Authenticaition객체 내부로 들어가고
	//시큐리티 session에는 Authenticaition이 session내부에 쏙들어간다.
	
	
	//함수 종료시@AuthenticationPrincipal 어노테이션이 만들어진다
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userEntity = userRepository.findByUsername(username);
		if(userEntity != null) {
			return new PrincipalDetails(userEntity);
		}
		return null;
	}

}
