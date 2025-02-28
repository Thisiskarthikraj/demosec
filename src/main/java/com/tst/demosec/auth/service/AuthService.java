package com.tst.demosec.auth.service;


import com.tst.demosec.auth.dto.ApiResponse;
import com.tst.demosec.auth.dto.AuthResponse;
import com.tst.demosec.auth.dto.LoginRequest;
import com.tst.demosec.auth.model.User;
import com.tst.demosec.auth.repo.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final SecurityContextRepository securityContextRepository =new HttpSessionSecurityContextRepository();;


    public ResponseEntity<?> register(User user) {
        Optional<User> exUser = userRepository.findByUsername(String.valueOf(user.getUsername()));

        if (exUser.isPresent()) {
            return ResponseEntity.ok().body(new ApiResponse("The User name exists", HttpStatus.CONFLICT.value()));
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return ResponseEntity.ok().body(new ApiResponse("The User has been registered", HttpStatus.CREATED.value()));
    }

    public ResponseEntity<?> login(LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {

        UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());
        if ( !passwordEncoder.matches(loginRequest.getPassword(), userDetails.getPassword())) {
            return ResponseEntity.ok().body(new ApiResponse("Invalid username or password", HttpStatus.UNAUTHORIZED.value()));
        }


        // Authenticate user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );
        // Set security context
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        return ResponseEntity.ok().body( new AuthResponse("Successfully logged in", request.getSession().getId() ));

    }
    public void  logout(HttpSession session) {
        session.invalidate();
        SecurityContextHolder.clearContext();
    }


}

