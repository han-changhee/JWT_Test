package org.chhan.ex_jwt.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.chhan.ex_jwt.domain.User;
import org.chhan.ex_jwt.repository.UserRepository;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;

@RequiredArgsConstructor
@Service
@Slf4j
public class CustomUserDetailService  implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email);

        if (user != null) {
            if (!user.getRole().equals("admin")) {
                throw new DisabledException("ADMIN 권한 유저가 아닙니다.");
            }
            System.out.println("유저인증 성공");
            return createUserdetails(user);
        } else {
            throw new UsernameNotFoundException("존재하지 않는 계정");
        }
    }

    private UserDetails createUserdetails(User user) {
        Collection<? extends GrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority(user.getRole()));

        return new CustomUserDetail(
                user.getEmail(),
                user.getPassword(),
                authorities,
                user.getId(),
                user.getRole()
        );
    }
}
