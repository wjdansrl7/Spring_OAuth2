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
import org.springframework.security.oauth2.provider.OAuth2Authentication;
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
                OAuth2Authentication authentication = (OAuth2Authentication)
                        SecurityContextHolder.getContext().getAuthentication();
                Map<String, String> map = (HashMap<String, String>)
                        authentication.getUserAuthentication().getDetails();
                // convertUser() : 사용자의 인증된 소셜 미디어 타입에 따라 빌더를 사용하여 User 객체를 만들어주는 가교 역할, 카카오의 경우에는 별도의 메서드를 사용
                User convertUSer = convertUser(String.valueOf(authentication.
                        getAuthorities().toArray()[0]), map);

                user = userRepository.findByEmail(convertUSer.getEmail());
                if (user == null) {
                    user = userRepository.save(convertUSer);
                }

                setRoleIfNotSave(user, authentication, map);
                session.setAttribute("user", user);
            } catch (ClassCastException e) {
                return user;
            }
        }
        return user;
    }

    private User convertUser(String authority, Map<String, String> map) {
        if (FACEBOOK.isEquals(authority)) return getModernUser(FACEBOOK, map);
        else if (GOOGLE.isEquals(authority)) return getModernUser(GOOGLE, map);
        else if (KAKAO.isEquals(authority)) return getKakaoUser(KAKAO, map);
        return null;
    }

    // getModernUser() 메서드는 페이스북이나 구글과 같이 공통되는 명명규칙을 가진 그룹을 User 객체로 매핑해준다.
    private User getModernUser(SocialType socialType, Map<String, String> map) {
        return User.builder()
                .name(map.get("name"))
                .email(map.get("email"))
                .pincipal(map.get("id"))
                .socialType(socialType)
                .createdDate(LocalDateTime.now())
                .build();
    }

    private User getKakaoUser(SocialType socialType, Map<String, String> map) {
        HashMap<String, String> propertyMap = (HashMap<String, String>) (Object)
                map.get("properties");
        return User.builder()
                .name(propertyMap.get("nickname"))
                .email(map.get("kaccount_email"))
                .pincipal(String.valueOf(map.get("id")))
                .socialType(KAKAO)
                .createdDate(LocalDateTime.now())
                .build();
    }

    // 인증된 authentication이 권한을 갖고 있는지 체크하는 용도로 쓰인다. 만약 저장된 User 권한이 없으면 SecurityContextHolder를 사용하여
    // 해당 소셜 미디어 타입으로 권한을 저장
    private void setRoleIfNotSave(User user, OAuth2Authentication authentication, Map<String, String> map) {
        if (!authentication.getAuthorities().contains(new SimpleGrantedAuthority(user.getSocialType().getRoleType()))) {
            SecurityContextHolder.getContext().setAuthentication(new
                    UsernamePasswordAuthenticationToken(map, "N/A",
                    AuthorityUtils.createAuthorityList(user.getSocialType().
                    getRoleType())));
        }
    }


}
