package com.microservice.authenticationservice.service.impl;


import com.microservice.authenticationservice.dto.UserInfoDetails;
import com.microservice.authenticationservice.dto.UserResponse;
import com.microservice.authenticationservice.service.IAuthenticationService;
import com.microservice.authenticationservice.utils.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.security.auth.login.AccountLockedException;
import java.util.Date;

@Service
public class AuthenticationServiceImpl implements IAuthenticationService {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Value("${userService}")
    private String userService;
    @Value("${jwtService}")
    private String jwtService;

    @Override
    public LoginResponse signIn(String email, String password) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );
        RestTemplate restTemplate = new RestTemplate();
        String userServiceUrl = "http://" + userService + "/users/getByEmail/" + email;
        ResponseEntity<UserResponse> userResponse = restTemplate.getForEntity(userServiceUrl, UserResponse.class);
        UserResponse user = userResponse.getBody();

        String jwtServiceUrl = "http://" + jwtService + "/jwt/generateAccessToken?email=" + email;
        ResponseEntity<String> response = restTemplate.getForEntity(jwtServiceUrl, String.class);
        var accessToken = response.getBody();

        jwtServiceUrl = "http://" + jwtService + "/jwt/generateRefreshToken?email=" + email;
        response = restTemplate.getForEntity(jwtServiceUrl, String.class);
        var refreshToken = response.getBody();

        var resultResponse = new LoginResponse();
        resultResponse.setAccessToken(accessToken);
        resultResponse.setRefreshToken(refreshToken);
        return resultResponse;

    }

    @Override
    public LoginResponse refreshToken(String refreshToken) throws AccountLockedException {
        return null;
    }

    @Override
    public UserDetailsService userDetailsService() {
         return username -> {
             RestTemplate restTemplate = new RestTemplate();
             String userServiceUrl = "http://" + userService + "/users/getByEmail/" + username;
             ResponseEntity<UserResponse> userResponse = restTemplate.getForEntity(userServiceUrl, UserResponse.class);
             UserResponse user = userResponse.getBody();
             return map(user);
         };
    }

    private UserInfoDetails map(UserResponse user) {
        return new UserInfoDetails(user);
    }
}
