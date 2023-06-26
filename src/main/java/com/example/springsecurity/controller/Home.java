package com.example.springsecurity.controller;

import com.example.springsecurity.domain.User;
import com.example.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class Home {
    @GetMapping(value = "/whoami")
    public ResponseEntity<?> whoami(Authentication authentication) {
        return ResponseEntity.ok(null != authentication ? authentication.getName(): "Anonymous");
    }
}
