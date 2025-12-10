package com.example.notary.controller;
import com.example.notary.dto.Dtos.*;
import com.example.notary.service.NotaryService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class NotaryController {
    private final NotaryService service;
    public NotaryController(NotaryService service) { this.service = service; }
    @PostMapping("/register")
    public RegisterResponse register(@RequestBody RegisterRequest req) throws Exception {
        return service.register(req);
    }
    @PostMapping("/sign")
    public SignResponse sign(@RequestBody SignRequest req) throws Exception {
        return service.sign(req);
    }
}