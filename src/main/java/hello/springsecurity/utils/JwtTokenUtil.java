package hello.springsecurity.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

public class JwtTokenUtil {

    public static String createToken(String userName, String key, long expireTimeMs) {
        Claims claims = Jwts.claims(); //일종의 map
        claims.put("userName", userName);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis())) //만든 날짜
                .setExpiration(new Date(System.currentTimeMillis() + expireTimeMs)) //끝나는 날짜
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();
    }

    public static String getUserName(String token, String key) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token)
                .getBody().get("userName", String.class);
    }

    //반환이 true면 토큰 만료된 것.
    public static boolean isExpired(String token, String key) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token)
                .getBody().getExpiration().before(new Date());
    }
}
