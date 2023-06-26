package com.example.springsecurity.configuration;

import com.example.springsecurity.domain.Role;
import com.example.springsecurity.domain.User;
import com.example.springsecurity.domain.UserRole;
import com.example.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    @Autowired
    UserRepository userRepository;
    //...
    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public AuthenticationManager customAuthenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject
                (AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder());
        return authenticationManagerBuilder.build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.csrf()
//                .disable()
//                .authorizeRequests()
//                .and()
//                .httpBasic()
//                .and()
//                .formLogin()
//                //.loginPage("/") // (5)
//                .permitAll()
//                .and()
//                .authorizeRequests()
//                .anyRequest()
//                .permitAll()
//                .and()
//                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//        return http.build();
//    }
    @Bean
    public boolean seedUsers(@Autowired BCryptPasswordEncoder bCryptPasswordEncoder) {
        List<String> users = Arrays.asList(new String[]{"admin", "user"});
        List<User> userList = new ArrayList<>();
        users.forEach(i -> {
            User user = new User();
            user.setUsername(i);
            user.setPassword(bCryptPasswordEncoder.encode("testadmin"));
            Set<UserRole> roles = new HashSet<>();
            roles.add(new UserRole("ROLE_USER"));
            if (i.equals("admin")) {
                roles.add(new UserRole("ROLE_ADMIN"));
            }
            user.setUserRoles(roles);
            userList.add(user);
        });
        userRepository.saveAll(userList);
        return true;
    }
}

//https://spring.io/guides/tutorials/react-and-spring-data-rest/