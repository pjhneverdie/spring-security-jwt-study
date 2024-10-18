package org.example.aboutjwt.service;

import lombok.RequiredArgsConstructor;

import org.example.aboutjwt.domain.User;
import org.example.aboutjwt.repository.UserRepository;

import org.springframework.security.core.GrantedAuthority;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class JwtUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User foundUser = userRepository.findByName(username);

        if (foundUser == null) {
            return null;
        }

        return new UserDetails() {

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                Collection<GrantedAuthority> authorities = new ArrayList<>();

                authorities.add(new GrantedAuthority() {

                    @Override
                    public String getAuthority() {
                        return foundUser.getRole().toString();
                    }

                });

                return authorities;
            }

            @Override
            public String getPassword() {
                return foundUser.getPassword();
            }

            @Override
            public String getUsername() {
                return foundUser.getName();
            }

        };
    }


}
