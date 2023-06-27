package com.example.springsecurity.controller;

import com.example.springsecurity.domain.LoginInfo;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class Admin {
    //@RolesAllowed("ROLE_ADMIN")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String admin() {
        return "Hello Admin!";
    }

   //@RolesAllowed({ "ROLE_ADMIN", "ROLE_USER" })
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
    @GetMapping("/user")
    public String user() {
        return "Hello User!";
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginInfo loginInfo) {
        return null;
    }
}
