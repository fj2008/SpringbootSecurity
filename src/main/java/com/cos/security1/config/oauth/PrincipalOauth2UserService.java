package com.cos.security1.config.oauth;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.model.UserRepository;
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService{

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private UserRepository userRepository;
	//구글로 부터 받은 userRequest데이터에 대한 후처리되는함수
	//이 함수를 통해서 회원가입을 진행 시킨다.
	
	//함수 종료시@AuthenticationPrincipal 어노테이션이 만들어진다
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("ClientRegistration :"+userRequest.getClientRegistration());
		System.out.println("AccessToken :"+userRequest.getAccessToken());
		
		OAuth2User oAuth2User = super.loadUser(userRequest);
		
		//구글로그인버튼 클릭->구글로그인창->로그인을 완료->code를 리턴(OAuth-Client라이브러리)->AccessToken요청
		//userRequest정보->loadUser함수 호출->구글으로 부터 회원프로필 받아준다.
		System.out.println("getAttributes"+oAuth2User.getAttributes());
		
		String provider = userRequest.getClientRegistration().getClientId();//google
		String providerId = oAuth2User.getAttribute("sub");
		String username = provider+"_"+providerId; //google_105617652356040885552이렇게 됨
		//이렇게 되면 username이 충돌 날일이 없다.
		String password =bCryptPasswordEncoder.encode("25g");
		String email = oAuth2User.getAttribute("email");
		String role = "ROLE_USER";
		//아무나 가입시키거나 중복가입하면 안되기때문에 체크를해줘야함
		User userEntity = userRepository.findByUsername(username);
		
		if(userEntity ==null) {
		
			System.out.println("당신은 최초 구글로그인 사용자 입니다 자동 회원가입을 진행합니다.");
			
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
		}else {
			System.out.println("구글 로그인을 이미 한적이 있습니다. 이미 지동회원가입이 되어있습니다.");
		}
		
		return new PrincipalDetails(userEntity,oAuth2User.getAttributes());
	}
}
