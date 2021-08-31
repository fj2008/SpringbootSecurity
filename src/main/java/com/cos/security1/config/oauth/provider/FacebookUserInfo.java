package com.cos.security1.config.oauth.provider;

import java.util.Map;

public class FacebookUserInfo implements OAuth2Userinfo{

	private Map<String,Object> attribute; //oAuth2User.getAttributes()를 받는다
	
	public FacebookUserInfo(Map<String,Object> attribute) {
		this.attribute =attribute;
	}
	
	@Override
	public String getProviderId() {
		
		return (String)attribute.get("id");
	}

	@Override
	public String getProvider() {
		
		return "facebook";
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
