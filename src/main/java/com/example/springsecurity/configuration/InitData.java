package com.example.springsecurity.configuration;

import com.example.springsecurity.domain.User;
import com.example.springsecurity.domain.UserRole;
import com.example.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class InitData {
    UserRepository userRepository;
    public InitData(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
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
