package com.web.controller;

import com.web.domain.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 인증된 User 정보를 세션에 저장해주는 기능 생성 -> 기존 로직을 어노테이션을 사용하여 축소
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

//    @GetMapping(value = "/{facebook|google|kakao}/complete")
//    public String loginComplete(HttpSession session) {
//        /**
//         * SecurityContextHolder에서 인증된 정보를 OAuth2Authentication 형태로 받아옵니다. OAuth2Authentication은 기본적인 인증에 대한
//         * 정보뿐만 아니라 OAuth2 인증과 관련된 정보도 함께 제공합니다.
//         */
//        OAuth2Authentication authentication = (OAuth2Authentication)
//                SecurityContextHolder.getContext().getAuthentication();
//        /**
//         * 리소스 서버에서 받아온 개인정보를 getDetails()를 사용해 Map 타입으로 받을 수 있다.
//         */
//        Map<String, String> map = (HashMap<String, String>)
//                authentication.getUserAuthentication().getDetails();
//        // 세션에 빌더를 사용하여 인증된 User 정보를 User 객체로 변환하여 저장
//        session.setAttribute("user", User.builder()
//                .name(map.get("name"))
//                .email(map.get("email"))
//                .pincipal(map.get("id"))
//                .socialType(SocialType.FACEBOOK)
//                .createdDate(LocalDateTime.now())
//                .build()
//        );
//
//        return "redirect:/board/list";
//    }

    // 컨트롤러에 불필요한 로직 많아짐, 페이스북 인증만 사용가능, 구글이나 카카오로 인증받은 User를 처리하는 로직을 추가해야한다.
    // 실제로 카카오의 경우에는 getDetails()를 사용하여 개인정보를 가져와도 해당 키값이 다른 소셜 미디어와 다르기 때문에 따로 처리해줘야 한다.
    // -> AOP 구현 :
    // 1. 직접 AOP를 구현하는 방법, 2. 스프링의 전략 인터페이스 중 하나인 HandlerMethodArgumentResolver를 사용하는 방법
    @GetMapping("/{facebook|google|kakao}/complete")
    public String loginComplete(User user) {
        return "redirect:/board/list";
    }

}
