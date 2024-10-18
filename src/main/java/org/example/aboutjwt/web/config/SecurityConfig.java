package org.example.aboutjwt.web.config;

import jakarta.servlet.http.HttpServletRequest;

import lombok.RequiredArgsConstructor;

import org.example.aboutjwt.domain.Role;
import org.example.aboutjwt.util.JwtUtil;

import org.example.aboutjwt.web.filter.JwtFilter;
import org.example.aboutjwt.web.filter.LoginFilter;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Value("${login.param.username}")
    private String usernameParam;

    @Value("${cors.allowedOrigins}")
    private String[] allowedOrigins;

    @Value("${cors.allowedMethods}")
    private String[] allowedMethods;

    @Value("${cors.allowedHeaders}")
    private String[] allowedHeaders;

    @Value("${cors.allowedExposedHeaders}")
    private String[] allowedExposedHeaders;

    private final JwtUtil jwtUtil;

    private final AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors((cors) -> {
            cors.configurationSource(new CorsConfigurationSource() {

                @Override
                public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                    CorsConfiguration corsConfiguration = new CorsConfiguration();

                    // 서버에 요청할 수 있는 도메인들 설정.
                    corsConfiguration.setAllowedOrigins(Arrays.stream(allowedOrigins).toList());
                    // 서버에 요청을 보낼 때 헤더에 포함 시킬 수 있는 옵션들 설정.
                    corsConfiguration.setAllowedHeaders(Arrays.stream(allowedHeaders).toList());
                    // 서버에 요청을 보낼 때 사용할 수 있는 http 동사 설정.
                    corsConfiguration.setAllowedMethods(Arrays.stream(allowedMethods).toList());

                    /**
                     * 응답의 헤더에서 꺼낼 수 있는 값 설정.
                     * 만약 Authorization을 추가하지 않으면 프론트에서 jwt를 꺼낼 수 없음!!!
                     */
                    corsConfiguration.setExposedHeaders(Arrays.stream(allowedExposedHeaders).toList());

                    return corsConfiguration;
                }
            });
        });

        http.csrf((auth) -> auth.disable());
        http.formLogin((auth) -> auth.disable());
        http.httpBasic((auth) -> auth.disable());

        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/", "/join").permitAll()
                .requestMatchers("/admin").hasRole(Role.ROLE_ADMIN.toString().split("_")[1])
                .anyRequest().authenticated());

        LoginFilter loginFilter = new LoginFilter(jwtUtil, authenticationManager());
        loginFilter.setUsernameParameter(usernameParam);

        http.addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(new JwtFilter(jwtUtil), LoginFilter.class);

        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}
