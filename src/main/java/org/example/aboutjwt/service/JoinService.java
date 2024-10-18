package org.example.aboutjwt.service;

import lombok.RequiredArgsConstructor;

import org.example.aboutjwt.dto.JoinDTO;

import org.example.aboutjwt.domain.Role;
import org.example.aboutjwt.domain.User;

import org.example.aboutjwt.repository.UserRepository;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    public void join(JoinDTO joinDTO) {
        User foundUser = userRepository.findByName(joinDTO.getName());

        if (foundUser != null) {
            throw new IllegalStateException("User already exists");
        }

        String encodedPassword = bCryptPasswordEncoder.encode(joinDTO.getPassword());
        userRepository.save(new User(null, joinDTO.getName(), encodedPassword, Role.ROLE_ADMIN));
    }

}
