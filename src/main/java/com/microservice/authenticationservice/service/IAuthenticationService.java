package com.microservice.authenticationservice.service;

import com.microservice.authenticationservice.utils.LoginResponse;
import org.springframework.security.core.userdetails.UserDetailsService;


import javax.security.auth.login.AccountLockedException;

public interface IAuthenticationService {
    LoginResponse signIn(String email, String password);
    LoginResponse refreshToken(String refreshToken) throws AccountLockedException;
    UserDetailsService userDetailsService();
}
