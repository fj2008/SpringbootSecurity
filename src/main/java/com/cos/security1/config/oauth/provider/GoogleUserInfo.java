package com.cos.security1.config.oauth.provider;

import java.util.Map;

public class GoogleUserInfo implements OAuth2Userinfo{

	private Map<String,Object> attribute; //oAuth2User.getAttributes()를 받는다
	
	public GoogleUserInfo(Map<String,Object> attribute) {
		this.attribute =attribute;
	}
	
	@Override
	public String getProviderId() {
		
		return (String)attribute.get("sub");
	}

	@Override
	public String getProvider() {
		
		return "google";
	}

	@Override
	public String getEmail() {
		
		return (String)attribute.get("email");
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return  (String)attribute.get("name");
	}

}
