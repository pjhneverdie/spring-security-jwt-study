package org.example.aboutjwt.web.controller;

import lombok.RequiredArgsConstructor;

import org.example.aboutjwt.dto.JoinDTO;
import org.example.aboutjwt.service.JoinService;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String join(JoinDTO joinDTO) {
        joinService.join(joinDTO);
        return "ok";
    }

}
