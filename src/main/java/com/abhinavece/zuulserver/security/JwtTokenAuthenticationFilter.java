package com.abhinavece.zuulserver.security;

import com.abhinavece.zuulserver.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

//import com.abhinavece.config.security.JwtConfig;

public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;

    public JwtTokenAuthenticationFilter(JwtConfig jwtConfig){
        this.jwtConfig = jwtConfig;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 1. Get authentication header, tokens are supposed to pass the authentication header
        String header = request.getHeader(jwtConfig.getHeader());

        // 2. Validate the header and check the prefix
        if(header == null || !header.startsWith(jwtConfig.getPrefix())){
            filterChain.doFilter(request, response);
            return;
        }

        // If no token is provided hence user wont be authenticated
        // Its fine, since user is trying to request for authentication or accessing a public path

        // 3. get the token from header
        String token  = header.replace(jwtConfig.getPrefix(), "");

        try {
            // exceptions might be thrown in creating the claims if for example the token is expired
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtConfig.getSecret().getBytes())
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            System.out.println("********** username fetched ********** " + username);

            if (null != username) {
                // List all authorities of the user
                List<String> authorities = (List<String>) claims.get("authorities");

                //5. Create Auth object
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

                // 6. Authenticate the user, now user is Authenticated
                SecurityContextHolder.getContext().setAuthentication(auth);
            }

        }catch (Exception e){
            // In case of failure. Make sure it's clear; so guarantee user won't be authenticated
            SecurityContextHolder.clearContext();
        }

        // go to next level of filter chain
        filterChain.doFilter(request, response);
    }
}
