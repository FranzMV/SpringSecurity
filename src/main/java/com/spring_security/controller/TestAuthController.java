package com.spring_security.controller;

import com.spring_security.constants.SecurityConstants;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(SecurityConstants.METHOD_PATH)
public class TestAuthController {

    @GetMapping(SecurityConstants.GET_PATH)
    public String helloGet(){
        return "Hello World - GET";
    }

    @PostMapping(SecurityConstants.POST_PATH)
    public String helloPost(){
        return "Hello World - POST";
    }

    @PutMapping(SecurityConstants.PUT_PATH)
    public String helloPut(){
        return "Hello World - PUT";
    }

    @DeleteMapping(SecurityConstants.DELETE_PATH)
    public String helloDelete(){
        return "Hello World - DELETE";
    }

    @PatchMapping(SecurityConstants.PATCH_PATH)
    public String helloPatch() {
        return "Hello World - PATCH";
    }

}
