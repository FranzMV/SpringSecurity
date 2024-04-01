package com.spring_security.config;

import com.spring_security.config.filter.JwtTokenValidator;
import com.spring_security.constants.SecurityConstants;
import com.spring_security.service.UserDetailServiceImpl;
import com.spring_security.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtUtils jwtUtils;

    /**
     * FilterChain
     * @param httpSecurity httpSecurity
     * @return SecurityFilterChain httpSecurity
     * @throws Exception exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http -> {

                    //Configurar los endPoints publicos
                    http.requestMatchers(HttpMethod.POST,"/auth/**").permitAll();
                    //Configurar los endPoints privados

                    http.requestMatchers(HttpMethod.POST, "/method/post")
                            .hasAnyRole(SecurityConstants.ADMIN_ROLE,SecurityConstants.DEVELOPER_ROLE);

                    http.requestMatchers(HttpMethod.PATCH,"/method/patch")
                            .hasAnyAuthority("REFACTOR");

                    http.requestMatchers(HttpMethod.GET,"/method/get")
                            .hasAnyAuthority("CREATE");

                    //Configurar resto de endPoints no especificados
                    http.anyRequest()
                            .denyAll();//No dejara pasar a nadie que no sea cualquiera de los especificados arriba
                            //.authenticated(); Cualquier endPoint no especificado arriba, le dejara pasar
                })
                .addFilterBefore(new JwtTokenValidator(jwtUtils), BasicAuthenticationFilter.class)
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
