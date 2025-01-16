package org.chhan.ex_jwt.auth;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
public class CustomUserDetail extends User {
    private final long id;
    private final String role;

    public CustomUserDetail(String email, String password, Collection<? extends GrantedAuthority> authorities, long id, String role) {
        super(email, password, authorities);
        this.id = id;
        this.role = role;
    }

}
