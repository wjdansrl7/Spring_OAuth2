package com.web.config;

import com.web.domain.enums.SocialType;
import com.web.oauth.ClientResources;
import com.web.oauth.UserTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.social.FacebookAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

import static com.web.domain.enums.SocialType.*;

/**
 * 각 소셜 미디어 리소스 정보를 빈으로 등록
 * WebSecurityConfigurerAdapter: 자동 설정 그대로 사용할 수도 있지만, 요청, 권한, 기타 설정에 대해서는 필수적으로 최적화한 설정이 들어가야 한다.
 * 최적화 설정을 위해 WebSecurityConfigurerAdapter를 상속받고 configure(HttpSecurity http) 메서드를 오버라이드 하여 원하는 형식의 시큐리티 설정을 합니다.
 *
 * OAuth2의 권한 부여 서버 : @EnableAuthorizationServer, 리소스 서버: @EnableResourceServer -> 권한 및 User 정보를 가져오는 서버를 직접 구성하지 않고
 * 모두 각 소셜 미디어의 서버를 사용하기 때문에 두 어노테이션을 사용할 필요는 없음.
 */
@Configuration
@EnableWebSecurity // 웹에서 시큐리티 기능을 사용하겠다는 어노테이션 -> 스프링 부트에서는 @EnableWebSecurity를 사용하면 자동 설정
@EnableOAuth2Client // OAuth2 설정
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2ClientContext oAuth2ClientContext;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CharacterEncodingFilter filter = new CharacterEncodingFilter();

        // 시큐리티의 설정
        /**
         * authorizeRequests(): 인증 메커니즘을 요청한 HttpServletRequest 기반으로 설정
         * - antMatchers(): 요청 패턴을 리스트 형식으로 설정
         * - permitAll(): 설정한 리퀘스트 페턴을 누구나 접근할 수 있도록 허용
         * - anyRequest(): 설정한 요청 이외의 리퀘스트 요청을 표현
         * - authenticated(): 해당 요청은 인증된 사용자만 할 수 있습니다.
         * headers(): 응답에 해당하는 header를 설정합니다. 설정하지 않으면 디폴트값으로 설정된다.
         * - frameOptions().disable(): XFrameOptionsHeaderWriter의 최적화 설정을 허용하지 않겠다
         * authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")): 인증의 진입 지점, 인증되지 않은 사용자가 허용되지 않은 경로로
         * 리퀘스트를 요청할 경우 '/login'으로 이동
         * formLogin().successForwardUrl("/board/list"): 로그인에 성공하면 설정된 경로로 포워딩된다.
         * logout(): 로그아웃에 대한 설정을 할 수 있다. 코드에서는 로그아웃이 수행될 URL(logoutUrl),
         * 로그아웃이 성공했을 때 포워딩될 URL(logoutSuccessUrl), 로그아웃을 성공했을 때, 삭제될 쿠키 값(deleteCookie), 설정된 세션의 무효화(invalidateHttpSession)를
         * 수행하게끔 설정되어 있음
         * addFilterBefore(filter, beforeFilter): 첫 번째 인자보다 먼저 시작될 필터를 등록,
         * - addFilterBefore(filter, CsrfFilter.class): 문자 인코딩 필터(filter)보다 CsrfFilter를 먼저 실행하도록 설정
         */
        http.
                authorizeRequests()
                    .antMatchers("/", "/login/**", "css/**", "/images/**", "/js/**",
                        "/console/**").permitAll()
                    .antMatchers("/facebook").hasAuthority(FACEBOOK.getRoleType())
                    .antMatchers("/google").hasAuthority(GOOGLE.getRoleType())
                    .antMatchers("/kakao").hasAuthority(KAKAO.getRoleType())
                    .anyRequest().authenticated()
                .and()
                    .headers().frameOptions().disable()
                .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(
                        "/login"))
                .and()
                    .formLogin()
                    .successForwardUrl("/board/list")
                .and()
                    .logout()
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/")
                    .deleteCookies("JSESSIONID")
                    .invalidateHttpSession(true)
                .and()
                    .addFilterBefore(filter, CsrfFilter.class)
                    .addFilterBefore(oauth2Filter(), BasicAuthenticationFilter.class)
                    .csrf().disable();
    }

    // OAuth2 클라이언트용 시큐리티 필터인 OAuth2ClientContextFilter를 불러와서 올바른 순서로 필터가 동작하도록 설정
    // 스프링 시큐리티 필터가 실행되기 전에 충부닣 낮은 순서로 필터를 등록
    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(
            OAuth2ClientContextFilter filter
    ) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    // 각 소셜 미디어 필터를 리스트 형식으로 한꺼번에 설정하여 반환
    private Filter oauth2Filter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(oauth2Filter(facebook(), "/login/facebook", FACEBOOK));
        filters.add(oauth2Filter(google(), "/login/google", GOOGLE));
        filters.add(oauth2Filter(kakao(), "/login/kakao", KAKAO));
        filter.setFilters(filters);

        return filter;
    }

    // 소셜 미디어 타입을 받아서 필터 설정
    private Filter oauth2Filter(ClientResources client, String path,
                                SocialType socialType) {
        OAuth2ClientAuthenticationProcessingFilter filter =
                new OAuth2ClientAuthenticationProcessingFilter(path); // 인증이 수행될 경로를 넣어 OAuth2 클라이언트 인증 처리 필터를 생성
        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(),
                oAuth2ClientContext); // 권한 서버와의 통신을 위해 OAuth2RestTemplate을 생성한다. 이를 생성하기 위해선 client 프로퍼티 정보와 OAuth2ClientContext가 필요
        filter.setRestTemplate(template);
        /**
         * User의 권한을 최적화해서 생성하고자 UserInfoTokenServices를 상속받은 UserTokenService를 생성, OAuth2 Access Token 검증을 위해 생성한 UserTokenService를 필터의 토큰 서비스로 등록
         */
        filter.setTokenServices(new UserTokenService(client, socialType));
        filter.setAuthenticationSuccessHandler((request, response, authentication) // 인증이 성공되면 리다이렉트될 URL 설정
                -> response.sendRedirect("/" + socialType.getValue() +
                "/complete")); // 인증완료: 리소스 서버에서 User에 대한 정보까지 챙겨왔다는 것을 의미 -> SecurityContextHolder에 그 정보가 저장되어있음.
        filter.setAuthenticationFailureHandler((request, response, exception) -> // 인증이 실패하면 필터에 리다이렉트될 URL 설정
                response.sendRedirect("/error"));
        return filter;
    }

    @Bean
    @ConfigurationProperties("facebook")
    public ClientResources facebook() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("google")
    public ClientResources google() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("kakao")
    public ClientResources kakao() {
        return new ClientResources();
    }
}
