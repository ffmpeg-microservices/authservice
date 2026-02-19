package com.mediaalterations.authservice.config;


import com.mediaalterations.authservice.entity.Auth;
import com.mediaalterations.authservice.repository.AuthRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final AuthRepository authRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if(header == null || !header.startsWith("Bearer")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.split("Bearer")[1];

        if(jwtUtil.isValid(token)){
            String username = jwtUtil.getUsername(token);
            if(username != null && SecurityContextHolder.getContext().getAuthentication()==null){

                Auth user = authRepository.findByUsername(username).orElseThrow(()-> new UsernameNotFoundException("Username not found"));

                UsernamePasswordAuthenticationToken userAuthToken =new UsernamePasswordAuthenticationToken(
                    user,null,user.getAuthorities()
                );
                SecurityContextHolder.getContext().setAuthentication(userAuthToken);
            }
        }

        filterChain.doFilter(request,response);

    }
}
