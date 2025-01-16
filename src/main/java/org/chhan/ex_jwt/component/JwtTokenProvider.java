package org.chhan.ex_jwt.component;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.chhan.ex_jwt.Util;
import org.chhan.ex_jwt.auth.CustomUserDetail;
import org.chhan.ex_jwt.domain.User;
import org.chhan.ex_jwt.dto.JwtToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;

@Slf4j
@Component
public class JwtTokenProvider {

    private final Key key;
    private final long ACCESS_TOKEN_VALID_TIME = Duration.ofMinutes(20).toMillis();
    private final long REFRESH_TOKEN_VALID_TIME = Duration.ofDays(7).toMillis();


    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /** SSR2OSR Backend 소스 코드 참고 **/
    // 요청에서 Token 추출, (email, password, token)
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    // JWT Token에서 특정 클레임 추출
    public <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwtToken);
        return claimsResolver.apply(claims);
    }

    // JWT 토큰에서 모든 클레임 추출
    private Claims extractAllClaims(String jwtToken) {
        // 찾은 예제와 차이점은 key를 String에서 추출한 byte가 아니라 decoding한 key값임
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwtToken).getBody();
    }

    // User 정보를 통해 AccessToken / Refresh Token 발급
    public JwtToken generateToken(Authentication authentication) {
        User user = new User();

        // autentication에서 User Email 추출
        CustomUserDetail userDetail = (CustomUserDetail) authentication.getPrincipal();
        String email = userDetail.getUsername();
        long id = userDetail.getId();

        Date now = new Date();

        // Access Token 생성
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("email", email) // 불러오고자 하는 정보들
                .claim("id", id) // 불러오고자 하는 정보들
                .claim("type", "acT")
                .setExpiration(new Date(now.getTime() + ACCESS_TOKEN_VALID_TIME))
                .signWith(key, SignatureAlgorithm.HS256).compact();

        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .claim("email", email) // 불러오고자 하는 정보들
                .claim("id", id) // 불러오고자 하는 정보들
                .claim("type", "reT")
                .setExpiration(new Date(now.getTime() + REFRESH_TOKEN_VALID_TIME))
                .signWith(key, SignatureAlgorithm.HS256).compact();

        user.setId(id);
        user.setEmail(email);
        user.setCurrentRefreshToken(refreshToken);
        user.setRole(userDetail.getRole());

        return JwtToken.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .user(user)
                .build();
    }

    // Jwt 토큰을 복호화 하여 토큰에 들어있는 정보를 꺼내는 메서드
    public Authentication getAuthentication(String token) {
        // Jwt 토큰 복호화
        Claims claims = parseClaims(token);
        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 클레임에서 권한정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .toList();

        return null;
    }

    public String validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return "Success";
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            return "Invalid";
        } catch (ExpiredJwtException e) {
            return "Expired";
        } catch (UnsupportedJwtException e) {
            return "Unsupported";
        } catch (IllegalArgumentException e) {
            return "JWT claims string is empty.";
        }
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }



    // accessToken 재발급
    public String accessTokenReissuance(User user) {
        Date now = new Date();
        return Jwts.builder()
                .claim("email", user.getEmail()) // 불러오고자 하는 정보들
                .claim("id", user.getId()) // 불러오고자 하는 정보들
                .claim("type", "acT")
                .setExpiration(new Date(now.getTime() + ACCESS_TOKEN_VALID_TIME))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String tokenTypeCheck(String token) {
        Base64.Decoder decoder = Base64.getDecoder();
        String[] tokenSplit = token.split("\\.");
        String decodedToken = new String(decoder.decode(tokenSplit[1]), StandardCharsets.UTF_8);

        Map<String, Object> convertMap = Util.jsonToMap(decodedToken);
        return convertMap.get("type").toString();
    }















    /** Test 해보려한 소스코드 **/
//    // JWT Token에서 email 추출
//    public String extractEmail(String jwtToken) {
//        return extractClaim(jwtToken, Claims::getSubject);
//    }
//
//    // JWT Token에서 만료 시간 추출
//    public Date extractExpiration(String jwtToken) {
//        return extractClaim(jwtToken, Claims::getExpiration);
//    }
//
//    // JWT Token에서 특정 클레임 추출
//    public <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver) {
//        final Claims claims = extractAllClaims(jwtToken);
//        return claimsResolver.apply(claims);
//    }
//
//    // JWT 토큰에서 모든 클레임 추출
//    private Claims extractAllClaims(String jwtToken) {
//        // 찾은 예제와 차이점은 key를 String에서 추출한 byte가 아니라 decoding한 key값임
//        return Jwts
//                .parserBuilder()
//                .setSigningKey(key).build()
//                .parseClaimsJws(jwtToken).getBody();
//    }
//
//    // JWT 토큰이 만료되었는지 확인
//    private Boolean isTokenExpired(String token) {
//        return extractExpiration(token).before(new Date());
//    }
//
//    // 사용자 정보 기반으로 JWT 토큰 생성
//    public String generateToken(CustomUserDetail customUserDetail) {
//        Map<String, Object> claims = new HashMap<>();
//
//        return createToken(claims, customUserDetail.getUsername());
//    }
//
//    // 클래임과 주제를 기반으로 JWT 토큰 생성
//    private String createToken(Map<String, Object> claims, String subject) {
//        Date now = new Date();
//
//        String accessToken = Jwts.builder()
//                .setClaims(claims)
//                .setSubject(subject)
//                .setIssuedAt(new Date(System.currentTimeMillis()))
//                .setExpiration(new Date(now.getTime() + ACCESS_TOKEN_VALID_TIME))
//                .signWith(key, SignatureAlgorithm.HS256).compact();
//
//        return accessToken;
//    }
//
//    // JWT 토큰의 유효성 검사
//    public Boolean validateToken(String token, CustomUserDetail customUserDetail) {
//        final String email = extractEmail(token);
//        return (email.equals(customUserDetail.getUsername()) && !isTokenExpired(token));
//    }













}
