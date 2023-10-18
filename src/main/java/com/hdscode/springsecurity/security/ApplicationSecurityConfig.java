package com.hdscode.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.hdscode.springsecurity.security.ApplicationUserRoles.ADMIN;
import static com.hdscode.springsecurity.security.ApplicationUserRoles.STUDENT;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig{

    // example using password encoder -> bcrypt (autowired from class PasswordConfig)
    private final PasswordEncoder passwordEncoder;
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((requests) -> requests
                        // example to permit access without authentication
                        .requestMatchers("/index.html", "/","/static/**").permitAll()
                        .requestMatchers("/api/**").hasRole(STUDENT.name())
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.builder()
                .username("luffy")
                .password(passwordEncoder.encode("password"))
                .roles(STUDENT.name())
                .build();

        UserDetails user2 = User.builder()
                .username("nami")
                .password(passwordEncoder.encode("password"))
                .roles(ADMIN.name())
                .build();

        return new InMemoryUserDetailsManager(
                user1,
                user2
        );
    }
}
