package com.hdscode.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.hdscode.springsecurity.security.ApplicationUserRoles.*;
import static com.hdscode.springsecurity.security.ApplicationUserPermission.*;

@Configuration
@EnableWebSecurity
// using annotation in controller preAuthorize
@EnableMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig{

    // example using password encoder -> bcrypt (autowired from class PasswordConfig)
    private final PasswordEncoder passwordEncoder;
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // spring security 6. manual using tokenrepository and token handler
//                .csrf((csrf) -> csrf
//                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
//                )

                // disable csrf
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((requests) -> requests
                        // example to permit access without authentication
                        .requestMatchers("/index.html", "/login.html","/static/**").permitAll()

                        // example to permit student role to access /api/** end point
//                        .requestMatchers("/api/**").hasRole(STUDENT.name())

//                        // example to permit by ist permission
//                        .requestMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                        .anyRequest().authenticated()

                )
                // form login - dont know why, but it works if httpBasic is disabled
                // using default redirect after success login
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                        .defaultSuccessUrl("/courses", true)
                        // define parameter (this is actually default parameter)
                        .passwordParameter("password")
                        .usernameParameter("username")
                )



//                .httpBasic(Customizer.withDefaults());
                .rememberMe(rememberMe ->
                        rememberMe
                                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                                .key("very secured")
                // remember me paramater
                                .rememberMeParameter("remember-me")
                )

                // logout implementation
                .logout(logout -> logout
                                .logoutUrl("/logout")
                        // using logout request mathcher if csrf is disable because logout using GET. if using csrf (default logout will be using POST
                                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                                .invalidateHttpSession(true)
                                .clearAuthentication(true)
                                .deleteCookies("JSESSIONID", "remember-me")
                                .logoutSuccessUrl("/login")
                        );
//                .rememberMe(Customizer.withDefaults());
        return http.build();
    }


    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.builder()
                .username("luffy")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name())
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails user2 = User.builder()
                .username("nami")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails user3 = User.builder()
                .username("zoro")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                user1,
                user2,
                user3
        );
    }
}
