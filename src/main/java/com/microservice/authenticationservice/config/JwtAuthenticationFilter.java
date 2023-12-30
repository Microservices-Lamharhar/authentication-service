package com.microservice.authenticationservice.config;

import com.microservice.authenticationservice.dto.UserResponse;
import com.microservice.authenticationservice.service.IAuthenticationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
   // private static Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Value("${userService}")
    private String jwtService;
    @Value("${userService}")
    private String userService;
    @Autowired
    private IAuthenticationService authenticationService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        System.out.println(request.getServletPath());
        if(request.getServletPath().contains("/auth/signin")
                || request.getServletPath().contains("/api/refreshToken")) {
            filterChain.doFilter(request, response);
            System.out.println("here");
            return ;
        }
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if (authHeader == null) {
            // filterChain.doFilter(request, response);
            response.setContentType("text/plain");
            response.getWriter().write("erreur : jwt no header" );
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return ;
        }

        jwt = authHeader.substring(7);
        RestTemplate restTemplate = new RestTemplate();
        String jwtServiceUrl = "http://" + jwtService + "/jwt/validateAccessToken/" + jwt;
        ResponseEntity<Boolean> jwtResponse = restTemplate.getForEntity(jwtServiceUrl, Boolean.class);
        var isAccessTokenValid = jwtResponse.getBody();
        if (!isAccessTokenValid) {
          //  filterChain.doFilter(request, response);
            try {
                throw new Exception("error");
            } catch (Exception e) {
                e.printStackTrace();
            }
            response.setContentType("text/plain");
            response.getWriter().write("erreur : jwt non valide" );
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);


        }

        jwtServiceUrl = "http://" + jwtService + "/jwt/extractUsername/" + jwt;
        ResponseEntity<String> jwtResponse2 = restTemplate.getForEntity(jwtServiceUrl, String.class);
        var extractedUsername = jwtResponse2.getBody();
        userEmail = extractedUsername;

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null)
        {
            UserDetails userDetails = authenticationService.userDetailsService().loadUserByUsername(userEmail);
           // if (jwtService.isTokenValid(jwt, userDetails)) {
             if (true) {
                System.out.println("JWT TOKEN IS VALID");
            //    logger.info("JWT TOKEN IS VALID");
                String authorities = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining());
          //      logger.info("user auhtorities : {}", authorities);
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                context.setAuthentication(authToken);
                SecurityContextHolder.setContext(context);
            } else {
                 response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                System.out.println("INVALID JWT TOKEN");
            }
        }
        filterChain.doFilter(request, response);
    }
}
