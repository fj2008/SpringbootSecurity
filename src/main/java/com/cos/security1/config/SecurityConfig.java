package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;

@Configuration// ioc등록
//활성화를 시키기 위해 @EnableWebSecurity를 해준다
//이 어노테이션을 활성화하면
//스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다.
//스프링 시큐리터 필터는 해당 java파일을 말하는것이다.
@EnableWebSecurity

//@Secured 어노테이션 활성화
//prePostEnabled = true설정은 preAuthorize/postAuthorize라는 어노테이션 활성화
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	
	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;
	
	//bean어노테이션을 적으면
	//해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
	//그럼 어디서든 쓸수 있게 된다는뜻
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
		.antMatchers("/user/**").authenticated()
		.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN')or hasRole('ROLE_MANAGER')")
		.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll()
		.and()
		.formLogin()
		.loginPage("/loginForm")
		.loginProcessingUrl("/login")
		//login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해준다.
		//이렇게 되면 컨트롤러에 /login을 만들지 않아도된다
		//왜냐하면 security가 대신 낚아채서 로그인을 진행하기때문이다
		.defaultSuccessUrl("/")
		.and()
		.oauth2Login()
		.loginPage("/loginForm")
		.userInfoEndpoint()
		.userService(principalOauth2UserService)
		;
		
		
	}
	
	
}
