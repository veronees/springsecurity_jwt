package hello.springsecurity.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 *
 * 꼭! SecurityConfig와 BCryptPasswordEncoder는 다른 클래스 선언함
 * 이후에 순환참조 문제가 발생할 수 있기 때문임
 *
 */

@Configuration
public class EncoderConfig {

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
}
