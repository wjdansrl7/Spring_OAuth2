package com.web.resolver;

import com.web.annotation.SocialUser;
import com.web.domain.User;
import com.web.domain.enums.SocialType;
import com.web.repository.UserRepository;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpSession;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static com.web.domain.enums.SocialType.*;

/**
 * supportsParameter() 메서드에 해당하는 어노테이션 타입이 명시되어 있는지 확인하는 로직 추가
 * 세션에서 User 객체를 가져오는 resolveArgument() 메서드 구현
 *
 * UserArgumentResolver 클래스에 User 정보를 받아오는 부분 추가
 */

@Component
public class UserArgumentResolver  implements HandlerMethodArgumentResolver {

    private final UserRepository userRepository;

    public UserArgumentResolver(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterAnnotation(SocialUser.class) != null &&
                parameter.getParameterType().equals(User.class);
    }

    // 세션은 RequestContextHandler를 사용해서 가져올 수 있다.
    @Override
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer, NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) throws Exception {
        HttpSession session = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest().getSession();
        User user = (User) session.getAttribute("user");
        return getUser(user, session);
    }

    private User getUser(User user, HttpSession session) { // 인증된 User 객체를 만드는 메인 메서드
        if (user == null) {
            try {
                /*
                2.0 버전에서는 기존의 OAuth2Authentication이 아닌 엑세스 토큰가지 제공한다는 의미에서 OAuth2AuthenticationToken을 지원
                SecurityContextHolder에서 OAuth2AuthenticationToken을 가져온다.
                 */
                OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) SecurityContextHolder.
                        getContext().getAuthentication();
                /*
                개인정보를 getAttributes() 메서드를 사용해 Map 타입으로 불러옵니다. 기존에는 Map<String, String>이었다면 이제는 Map<String, Object>
                를 제공하게끔 변경되었으므로 Map 객체를 사용하는 부분을 모두 Map<String, Object>로 변경
                 */
                Map<String, Object> map = authentication.getPrincipal().getAttributes();
                /*
                예전에는 getAuthorities() 메서드로 권한을 불러와서 인증된 소셜 미디어가 어디인지 알았다면, 이제는 getAuthorizedClientRegistrationId()
                메서드로 파악할 수 있습니다.
                 */
                User convertUser = convertUser(authentication.getAuthorizedClientRegistrationId(), map);

                user = userRepository.findByEmail(convertUser.getEmail());
                if (user == null) {
                    user = userRepository.save(convertUser);
                }

                setRoleIfNotSave(user, authentication, map);
                session.setAttribute("user", user);
            } catch (ClassCastException e) {
                return user;
            }
        }
        return user;
    }

    private User convertUser(String authority, Map<String, Object> map) {
        if (FACEBOOK.getValue().equals(authority)) return getModernUser(FACEBOOK, map);
        else if (GOOGLE.getValue().equals(authority)) return getModernUser(GOOGLE, map);
        else if (KAKAO.getValue().equals(authority)) return getKakaoUser(map);
        return null;
    }

    // getModernUser() 메서드는 페이스북이나 구글과 같이 공통되는 명명규칙을 가진 그룹을 User 객체로 매핑해준다.
    private User getModernUser(SocialType socialType, Map<String, Object> map) {
        return User.builder()
                .name(String.valueOf(map.get("name")))
                .email(String.valueOf(map.get("email")))
                .principal(String.valueOf(map.get("id")))
                .socialType(socialType)
                .createdDate(LocalDateTime.now())
                .build();
    }

    private User getKakaoUser(Map<String, Object> map) {
        HashMap<String, String> propertyMap = (HashMap<String, String>)
                map.get("properties");
        return User.builder()
                .name(propertyMap.get("nickname"))
                .email(String.valueOf(map.get("kaccount_email")))
                .principal(String.valueOf(map.get("id")))
                .socialType(KAKAO)
                .createdDate(LocalDateTime.now())
                .build();
    }

    // 인증된 authentication이 권한을 갖고 있는지 체크하는 용도로 쓰인다. 만약 저장된 User 권한이 없으면 SecurityContextHolder를 사용하여
    // 해당 소셜 미디어 타입으로 권한을 저장
    private void setRoleIfNotSave(User user, OAuth2AuthenticationToken authentication, Map<String, Object> map) {
        if (!authentication.getAuthorities().contains(new SimpleGrantedAuthority(user.getSocialType().getRoleType()))) {
            SecurityContextHolder.getContext().setAuthentication(new
                    UsernamePasswordAuthenticationToken(map, "N/A",
                    AuthorityUtils.createAuthorityList(user.getSocialType().
                    getRoleType())));
        }
    }


}
