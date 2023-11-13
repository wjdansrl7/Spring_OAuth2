package com.web.config;

import com.web.domain.enums.SocialType;
import com.web.oauth2.CustomOAuth2Provider;
import jdk.nashorn.internal.ir.IfNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

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
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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
                    .antMatchers("/", "/oauth2/**", "/login/**", "css/**", "/images/**", "/js/**",
                        "/console/**").permitAll()
                    .antMatchers("/facebook").hasAuthority(FACEBOOK.getRoleType())
                    .antMatchers("/google").hasAuthority(GOOGLE.getRoleType())
                    .antMatchers("/kakao").hasAuthority(KAKAO.getRoleType())
                    .anyRequest().authenticated()
                .and()
                    .oauth2Login()
                    .defaultSuccessUrl("/loginSuccess")
                    .failureUrl("/loginFailure")
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
                    .csrf().disable();
    }

    // 카카오 로그인 연동을 위한 설정 코드 추가
    /*
    OAuth2ClientProperties와 카카오 클라이언트 ID를 불러옵니다. 다시 한번 설명하자면 @Configuration으로 등록되어 있는 클래스에서 @Bean으로 등록된
    메서드의 파라미터로 지정된 객체들은 오토와이어링(autowiring)할 수 있습니다. OAuth2ClientProperties에는 구글과 페이스북의 정보가 들어 있고,
    카카오는 따로 등록했기 때문에 @Value 어노테이션을 사용하여 수동으로 불러옵니다.
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(
            OAuth2ClientProperties oAuth2ClientProperties, @Value(
            "${custom.oauth2.kakao.client-id}") String kakaoClientId) {

        /*
         registrations 리스트에 카카오 인증 정보를 추가합니다. 실제 요청 시 사용하는 정보는 클라이언트 ID뿐이지만, clientSecret()과 jwtSetUri()가
         null이면 안 되므로 임시값을 넣었습니다.
         */

        List<ClientRegistration> registrations = oAuth2ClientProperties.getRegistration().keySet().stream()
                .map(client -> getRegistration(oAuth2ClientProperties, client))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        registrations.add(CustomOAuth2Provider.KAKAO.getBuilder("kakao")
                .clientId(kakaoClientId)
                .clientSecret("test") // 필요없는 값이지만 null이면 실행이 안되므로 임시값을 넣었음
                .jwkSetUri("test")  // 필요없는 값이지만 null이면 실행이 안되므로 임시값을 넣었음
                .build());

        return new InMemoryClientRegistrationRepository(registrations);
    }

    /*
    getRegistration() 메서드를 사용해 구글과 페이스북의 인증 정보를 빌드시켜줍니다.
     */
    private ClientRegistration getRegistration(OAuth2ClientProperties clientProperties, String client) {
        if ("google".equals(client)) {
            OAuth2ClientProperties.Registration registration = clientProperties.getRegistration().get("google");
            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    .scope("email", "profile")
                    .build();
        }
        // 페이스북의 그래프 API의 경우 scope()로는 필요한 메서드를 반환해주지 않기 때문에 직접 id, name, eamil, link 등을 파라미터로 넣어
        // 요청하도록 설정했습니다.
        if ("facebook".equals(client)) {
            OAuth2ClientProperties.Registration registration = clientProperties.getRegistration().get("facebook");
            return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    .userInfoUri("https://graph.facebook.com/me?fields=id,name,email,link")
                    .scope("email")
                    .build();
        }
        return null;
    }


}
