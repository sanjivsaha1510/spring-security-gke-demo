package com.example.securingweb.controller;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class PublicController {

    // Stage 1: locked down like everything else.
    // Stage 2: opened up with permitAll().
    @GetMapping("/hello")
    public Map<String, String> hello() {
        return Map.of("message", "Hello! This endpoint is open to everyone.");
    }
}
