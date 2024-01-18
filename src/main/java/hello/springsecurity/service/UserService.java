package hello.springsecurity.service;

import hello.springsecurity.domain.User;
import hello.springsecurity.exception.AppException;
import hello.springsecurity.exception.ErrorCode;
import hello.springsecurity.repository.UserRepository;
import hello.springsecurity.utils.JwtTokenUtil;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder; //스프링빈에 등록한 BCryptPasswordEncoder를 주입받아 사용한다.
    @Value("${jwt.secret}")
    private String key;

    /**
     * 위의 @Value로 yml의 설정값을 받으니까 키의 bit크기가 너무 작다고 안된다고 함.
     * 그래서 밑의 Keys클래스의 secretKeyFor()메서드를 사용해서 적절한 크기의 를 생성해줌.
     */
//    private Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    private Long expireTimeMs = 1000 * 60 * 60L;

    public void join(String userName, String password) {

        //userName 중복 check
        userRepository.findByUserName(userName)
                .ifPresent(user -> {
                    throw new AppException(ErrorCode.USERNAME_DUPLICATED, userName + " 는 이미 있습니다.");
                });

        //저장
        User user = User.builder()
                .userName(userName)
                .password(encoder.encode(password)) //컨트롤러에서 넘겨받은 비밀번호로 user를 생성할 때 인코딩을 해준다.
                .build();

        userRepository.save(user);
    }

    public String login(String userName, String password) {
        //userName없음(ID가 없는 경우)
        User user = userRepository.findByUserName(userName)
                .orElseThrow(() ->
                        new AppException(ErrorCode.USERNAME_NOT_FOUND, userName + " 는 없습니다.")
                );

        //password가 틀린 경우 --> 위의 로직에서 예외가 안터지면 user가 있다는 것임으로 password 확인 로직으로 온다.
        if (!(encoder.matches(password, user.getPassword()))) {
            throw new AppException(ErrorCode.INVALID_PASSWORD, "패스워드를 잘못 입력했습니다.");
        }

        String token = JwtTokenUtil.createToken(user.getUserName(), key, expireTimeMs);


        // 앞에서 Exception안났으면 토큰 발짜
        return token;
    }
}
