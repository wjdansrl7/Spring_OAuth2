package com.web.oauth;


import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

/**
 * 소셜 미디어 리소스 프로퍼티를 객체로 매핑해주는 ClientResources 객체
 * @NestedConfigurationProperty : 해당 필드가 단일 값이 아닌 중복으로 바인딩된다고 표시하는 어노테이션, 소셜 미디어 세 곳의 프로퍼티를 각각 바인딩하므로 @NestedConfigurationProperty
 * 어노테이션을 붙임
 * ResourceServerProperties 객체는 원래 OAuth2 리소스 값을 매핑하는데 사용하지만 예제에서는 회원 정보를 얻는 userInfoUri 값을 받는 데 사용한다.
 */
public class ClientResources {

    @NestedConfigurationProperty
    private AuthorizationCodeResourceDetails client =
            new AuthorizationCodeResourceDetails();

    @NestedConfigurationProperty
    private ResourceServerProperties resource = new ResourceServerProperties();


    public AuthorizationCodeResourceDetails getClient() {
        return client;
    }

    public ResourceServerProperties getResource() {
        return resource;
    }



}
