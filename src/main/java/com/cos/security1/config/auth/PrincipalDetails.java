package com.cos.security1.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.cos.security1.model.User;

import lombok.Data;

//시큐리티가 /login주소 요청이 오면 낚아채서 로그인을 진행시킨다.
//로그인 진행이 완료가 되면security가 session을 만들어준다.
//일반적인 공간은 session이랑 똑같은 session 공간인데
//시큐리티가 자신만이 가지고있는 session이 있다(키값으로 구분한다는뜻)
//Security ContextHolder라는 키값에 session정보를 저장을시킨다.
//이때 여기에 들어갈수있는 오브젝트가 정해져있다
//오브젝트=>Authentication타입 객체만 가능
//Authentication 객체 안에 User정보가 있어야 됨.
//클래스도 정해져있음
//User오브젝트타입==>UserDetails타입 객체
//Security Session =>Authentication =>UserDetails(PrincipalDetails는상속받아서 같은 타입이됨)
@Data
public class PrincipalDetails implements UserDetails,OAuth2User{

	private User user;//콤포지션
	private Map<String,Object> attributes;
	
	//일반로그인 생성자
	public PrincipalDetails(User user) {
		this.user=user;
	}
	//oauth로그인 생성자
	public PrincipalDetails(User user,Map<String,Object>attributes) {
		this.user=user;
		this.attributes =attributes;
	}
	
	//해당 user의 권하는 리턴하는 곳!
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority>collect = new ArrayList<>();
		collect.add(new GrantedAuthority() {
			
			@Override
			public String getAuthority() {
				
				return user.getRole();
			}
		});
		return collect;
	}
	//패스워드 리턴하는자리
	@Override
	public String getPassword() {
		
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		
		return user.getUsername();
	}

	//너 계정 만료됐니? 물어보는거
	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	//너 계정 잠겼니?
	@Override
	public boolean isAccountNonLocked() {
		
		return true;
	}

	//너 비밀번호가 너무 오래동안 사용한거 아니니?
	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	//너 계정이 활성화 돼있니?
	@Override
	public boolean isEnabled() {
		//우리 사이트에서 1년동안 회원이 로그인을 안하면 ! 휴면계정으로 하기로함.
		//그럼 user모델 필드에 로그인 할때마다 로그인날자를 저장하도록 하고
		//user.getlogindate();
		//위와같이 가져와서
		//현재시간 -로그인시간 =>1년을 초과하면 return false;하면된다
		return true;
	}

	@Override
	public Map<String, Object> getAttributes() {
		
		return attributes;
	}

	@Override
	public String getName() {
		
		return null;
	}

	
	
}
