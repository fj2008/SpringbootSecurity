package com.cos.security1.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.model.UserRepository;



@Controller
public class IndexController {
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	
	
	@GetMapping("/test/login")
	public @ResponseBody String testLogin(Authentication authentication
			,@AuthenticationPrincipal PrincipalDetails userDetails) {
		System.out.println("/test/login===========================");
		PrincipalDetails principalDetails =(PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication:"+principalDetails.getUser());
		System.out.println("userDetails:"+userDetails.getUser());
		return"세션정보확인";
	}

	@GetMapping("/test/oauth/login")
	public @ResponseBody String testOauthLogin(Authentication authentication,@AuthenticationPrincipal OAuth2User oauth) {
		System.out.println("/test/oauth/login===========================");
		OAuth2User OAuth2User =(OAuth2User) authentication.getPrincipal();
		System.out.println("authentication:"+OAuth2User.getAttributes());
		System.out.println("oauth2User:"+oauth.getAttributes());
		return"Oauth세션정보확인";
	}
	
	
	@GetMapping({"","/"})
	public String index() {
		//머스테치 기본폴더 src/main/resources/
		//뷰리졸버 설정 : templates(prefix), .mustache(suffix)
		return "index";
		
	}
	
	@GetMapping("/user")
	public@ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("PrincipalDetails:"+principalDetails.getUser());
		return "user";
	}
	
	@GetMapping("/admin")
	public@ResponseBody String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	public@ResponseBody String manager() {
		return "manager";
	}
	
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@PostMapping("/join")
	public String join(User user) {
		user.setRole("ROLE_USER");
		
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		
		user.setPassword(encPassword);
		
		userRepository.save(user);
		//일반적인 회원가입처리는 이렇게 배웟다 
		//ex 비밀번호가 1234이렇게 첬다고하면
		//시큐리티로 로그인을 할 수 없다.
		//이유는 패스워드가 암호화가 안되었기때문이다.
		
		return "redirect:/loginForm";
	}
	//@Secured하나의 컨트롤러에서만 권한처리를 하고싶을때 사용하는어노테이션
	@Secured("ROLE_ADMIN")
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "개인정보";
		
	}
	//하나만 걸고 싶을때는@Secured를 사용하면되는데
	//여러게를 걸고 싶을때는@PreAuthorize를 사용한다.
	
	@PreAuthorize("hasRole('ROLE_MANAGER')or hasRole('ROLE_ADMIN')")
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터 정보";
		
	}

}
