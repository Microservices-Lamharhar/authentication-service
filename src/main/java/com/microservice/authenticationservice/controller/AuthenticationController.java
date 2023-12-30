package com.microservice.authenticationservice.controller;



import com.microservice.authenticationservice.dto.LoginResponse;
import com.microservice.authenticationservice.dto.UserInfoDetails;
import com.microservice.authenticationservice.dto.UserResponse;
import com.microservice.authenticationservice.service.IAuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
  @Autowired
  private IAuthenticationService authenticationService;

  @GetMapping("/test")
  public ResponseEntity<?> test() {

    return new ResponseEntity<>("OK", HttpStatus.OK);
  }

  @GetMapping("/signin")
  public ResponseEntity<?> generateAccessToken(@RequestParam String email, @RequestParam String password) {
    return new ResponseEntity<>(authenticationService.signIn(email, password), HttpStatus.OK);
  }

  @GetMapping("/processRequest")
  public ResponseEntity<String> processRequest() {
    try {
      return new ResponseEntity<>("OK",HttpStatus.OK);
    } catch (Exception e) {
      return new ResponseEntity<>("FORBIDDEN",HttpStatus.FORBIDDEN);
    }

  }



  private UserInfoDetails map(UserResponse user) {
    return new UserInfoDetails(user);
  }
}
