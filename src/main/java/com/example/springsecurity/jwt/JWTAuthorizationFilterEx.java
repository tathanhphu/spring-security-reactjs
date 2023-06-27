package com.example.springsecurity.jwt;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.example.springsecurity.jwt.SecurityConstants.HEADER_STRING;
import static com.example.springsecurity.jwt.SecurityConstants.TOKEN_PREFIX;
public class JWTAuthorizationFilterEx extends GenericFilter {
    private JwtTokenUtil jwtTokenUtil;

    public JWTAuthorizationFilterEx(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String header = req.getHeader(HEADER_STRING);

        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);

        if (token != null) {
            // parse the token.
            token = token.replace(TOKEN_PREFIX, "");
            String user = jwtTokenUtil.getUsernameFromToken(token);
            List<String> roles = jwtTokenUtil.getRoles(token);
            Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

            roles.forEach(role -> grantedAuthorities.add(new SimpleGrantedAuthority(role)));
            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, grantedAuthorities);
            }
            return null;
        }
        return null;
    }
}
