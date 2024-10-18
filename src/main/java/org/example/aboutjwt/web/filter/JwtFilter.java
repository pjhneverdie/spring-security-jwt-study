package org.example.aboutjwt.web.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.example.aboutjwt.domain.Role;
import org.example.aboutjwt.domain.User;

import org.example.aboutjwt.util.JwtUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

import java.util.ArrayList;
import java.util.Collection;


@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");

        if (authorization != null && authorization.startsWith("Bearer ")) {
            String token = authorization.split(" ")[1];

            System.out.println(token);

            if (jwtUtil.isExpired(token)) {
                log.info("만료된 토큰");
                filterChain.doFilter(request, response);
                return;
            }

            User user = new User(null, jwtUtil.getUsername(token), null, Role.valueOf(jwtUtil.getRole(token)));

            UserDetails userDetails = new UserDetails() {

                @Override
                public Collection<? extends GrantedAuthority> getAuthorities() {
                    Collection<GrantedAuthority> authorities = new ArrayList<>();

                    authorities.add(new GrantedAuthority() {

                        @Override
                        public String getAuthority() {
                            return user.getRole().toString();
                        }

                    });

                    return authorities;
                }

                @Override
                public String getPassword() {
                    return user.getPassword();
                }

                @Override
                public String getUsername() {
                    return user.getName();
                }

            };

            /**
             * 인증 전에는 사용자 이름이 토큰의 principal로 사용되지만,
             * 인증 후에는 AbstractUserDetailsAuthenticationProvider가 principal을 인증된 사용자 정보(UserDetails)로 교체하고
             * 이 교체된 UsernamePasswordAuthenticationToken이 SecurityContextHolder에 저장되는 게 기본적인 방식이기 때문에, 이에 똑같이 맞춰주는 것임
             */
            Authentication authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authToken);

            filterChain.doFilter(request, response);

            log.info("로그인한 유저");
        } else {
            filterChain.doFilter(request, response);
        }
    }

}
