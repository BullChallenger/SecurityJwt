package com.jwt.prac.jwt_with_security.security.config;

import com.jwt.prac.jwt_with_security.security.filter.JsonEmailPasswordAuthenticationFilter;
import com.jwt.prac.jwt_with_security.security.provider.JsonAuthenticationProvider;
import com.jwt.prac.jwt_with_security.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
public class SecurityConfig {

    @Autowired
    private LoginService loginService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin().loginProcessingUrl("/login").defaultSuccessUrl("/").failureUrl("/login")
            .and()
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                    .antMatchers("/login", "/signUp", "/").permitAll()
                .anyRequest().authenticated()
            .and()
                .addFilterAfter(jsonEmailPasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public JsonEmailPasswordAuthenticationFilter jsonEmailPasswordAuthenticationFilter() {
        JsonEmailPasswordAuthenticationFilter jsonAuthenticationFilter = new JsonEmailPasswordAuthenticationFilter();
        jsonAuthenticationFilter.setAuthenticationManager(authenticationManager());

        return jsonAuthenticationFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        JsonAuthenticationProvider jsonAuthenticationProvider = new JsonAuthenticationProvider();
        jsonAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        jsonAuthenticationProvider.setUserDetailsService(loginService);

        return new ProviderManager(jsonAuthenticationProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() { return PasswordEncoderFactories.createDelegatingPasswordEncoder(); }
}
