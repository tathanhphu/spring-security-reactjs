package com.example.springsecurity.service;
import java.util.HashSet;
import java.util.Set;

import com.example.springsecurity.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class MongoAuthUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    public MongoAuthUserDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

        com.example.springsecurity.domain.User user = userRepository.findUserByUsername(userName);

        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

        user.getAuthorities()
                .forEach(role -> {
                    grantedAuthorities.add(new SimpleGrantedAuthority(role.getRole()
                            .getName()));
                });

        return new User(user.getUsername(), user.getPassword(), grantedAuthorities);
    }

}
