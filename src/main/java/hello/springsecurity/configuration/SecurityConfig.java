package hello.springsecurity.configuration;

import hello.springsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // 스프링 Security 지원을 가능하게 함
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserService userService;

    @Value("${jwt.secret}")
    private String key;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorizeRequests -> {
                    authorizeRequests
                            .requestMatchers("/api/v1/users/join").permitAll() //로그인은 열어둠
                            .requestMatchers("/api/v1/users/login").permitAll() //회원가입 열어둠
//                            .requestMatchers("/api/v1/reviews").permitAll()
                            .requestMatchers(HttpMethod.POST, "/api/v1/**").authenticated(); //인증 필요
//                            .anyRequest().authenticated();
                        })
                .csrf(csrf -> {
                    csrf.disable();
                })
                .csrf(cors -> {
                    cors.disable();
                })
                .httpBasic(httpBasic -> {
                    httpBasic.disable();
                })
                .addFilterBefore(new JwtFilter(userService, key), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return new WebSecurityCustomizer() {
//            @Override
//            public void customize(WebSecurity web) {
//                web.ignoring().requestMatchers("/api/v1/users/join", "/api/v1/users/login");
//            }
//        };
//    }

    /**
     * 위 코드와 아래 코드 같음.
     */

    //    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//
//        return (web) -> web.ignoring().requestMatchers(
//                "/api/v1/users/join"
//        );
//    }
}
