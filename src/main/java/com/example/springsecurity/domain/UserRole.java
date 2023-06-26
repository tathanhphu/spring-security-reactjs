package com.example.springsecurity.domain;

import org.springframework.security.core.GrantedAuthority;

public class UserRole implements GrantedAuthority {

    private Role role;

    public UserRole() {

    }
    public UserRole(String role) {
        this.role = new Role(role);
    }
    @Override
    public String getAuthority() {
        return role.getName();
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }
}