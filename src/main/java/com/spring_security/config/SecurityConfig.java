package com.spring_security.config;

import com.spring_security.constants.SecurityConstants;
import com.spring_security.service.UserDetailServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * FilterChain
     * @param httpSecurity httpSecurity
     * @return SecurityFilterChain httpSecurity
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http -> {

                    //Configurar los endPoints publicos
                    http.requestMatchers(HttpMethod.GET,SecurityConstants.GET_PATH).permitAll();
                    //Configurar los endPoints privados

                    http.requestMatchers(HttpMethod.POST, SecurityConstants.POST_PATH)
                            .hasAnyRole(SecurityConstants.ADMIN_ROLE,SecurityConstants.DEVELOPER_ROLE);

                    http.requestMatchers(HttpMethod.PATCH,SecurityConstants.PATCH_PATH)
                            .hasAnyAuthority(SecurityConstants.REFACTOR_ROLE);

                    //Configurar resto de endPoints no especificados
                    http.anyRequest()
                            .denyAll();//No dejara pasar a nadie que no sea cualquiera de los especificados arriba
                            //.authenticated(); Cualquier endPoint no especificado arriba, le dejara pasar
                })
                .build();
    }



    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    /**
     * AuthenticationProvider para traer los usuarios de la BD
     * @return AuthenticationProvider provider
     */
    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailServiceImpl userDetailService){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userDetailService);
        return provider;
    }


    /**
     * Password encoder with BCryptPasswordEncoder
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder();}

}
