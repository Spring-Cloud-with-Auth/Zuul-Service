package com.abhinavece.zuulserver.security;

import com.abhinavece.zuulserver.config.JwtConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

@EnableWebSecurity
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .csrf().disable()
                // make sure we are stateless, we wont be using users state stored in session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                // attempts to authorize
                .and()
                .exceptionHandling().authenticationEntryPoint((request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                // Add filter to validate token with every request
                .addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
                // Authorize request config
                .authorizeRequests()
                // Allow all who are accessing auth service
                .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
                // Must be admin if trying to access admin area, authentication is also required here
                .antMatchers("/gallery" + "/admin/**").hasRole("ADMIN")
                // ANy other request must be authenticated
                .anyRequest().authenticated();

    }

    @Bean
    public JwtConfig jwtConfig(){
        return new JwtConfig();
    }
}
