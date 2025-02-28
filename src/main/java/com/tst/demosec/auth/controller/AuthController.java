package com.tst.demosec.auth.controller;

import com.tst.demosec.auth.dto.ApiResponse;
import com.tst.demosec.auth.dto.LoginRequest;
import com.tst.demosec.auth.model.User;
import com.tst.demosec.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
      return    authService.login(loginRequest, request, response);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        return authService.register(user);

    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpSession session) {
            authService.logout(session);
            return ResponseEntity.ok().body( new ApiResponse("logout Successfully", HttpStatus.OK.value()));
    }
    @GetMapping("/test")
    public void test() {

    }

}
