package com.spring_security.controller;

import com.spring_security.DTO.AuthLoginRequest;
import com.spring_security.DTO.AuthResponse;
import com.spring_security.constants.SecurityConstants;
import com.spring_security.service.UserDetailServiceImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(SecurityConstants.AUTH_PATH)
public class AuthenticationController {


    @Autowired
    private UserDetailServiceImpl userDetailService;

    @PostMapping(SecurityConstants.LOG_IN_PATH)
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid AuthLoginRequest userRequest){
        return new ResponseEntity<>(this.userDetailService.loginUser(userRequest), HttpStatus.OK);
    }
}
