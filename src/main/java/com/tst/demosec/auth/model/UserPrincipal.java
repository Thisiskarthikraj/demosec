package com.tst.demosec.auth.model;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.io.Serializable;

public class UserPrincipal implements UserDetails, Serializable {
    @Serial
    private static final long serialVersionUID = 1L; // Ensure proper serialization

    private final User user;

    public UserPrincipal(User user) {
        this.user = user;
    }

    @Override
    public String getUsername() { return user.getUsername(); }

    @Override
    public String getPassword() { return user.getPassword(); }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList(); // No roles for now
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}
