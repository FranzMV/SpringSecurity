package com.spring_security.config;

import com.spring_security.constants.SecurityConstants;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .authorizeHttpRequests(auth->{
                    //Todos los endpoints permitidos sin autenticacion
                    auth.requestMatchers(SecurityConstants.NON_NEEDED_SECURITY_ENDPOINT).permitAll();
                    //Necesitan autenticacion
                    auth.anyRequest().authenticated();
                })
                //Url donde se redirige al iniciar sesion
                .formLogin(fl->{
                    fl.successHandler(successHandler())
                    .permitAll();
                })
                //Politica de creacion y administracion de la sesion
                //ALWAYS-  Crea una sesion siempre y cuando no exista ninguna. SI hay una existente, la reutiliza
                // IF_REQUIRED - Crea una nueva sesion si es necesario. Si no existe la crea
                // NEVER - No crea ninguna sesion, pero si ya existe una sesion, la utiliza.
                // STATELESS - Todas las solicitudes las las trabaja de forma independiente y no guarda ninguna sesion
                .sessionManagement(sm->{
                    sm.sessionCreationPolicy(SessionCreationPolicy.ALWAYS);

                    //Si no se logra autenticar, si se crea una sesion erronea, a donde se va a rederigir al usuario
                    sm.invalidSessionUrl("/login");

                    //N'umero m'aximo de sesiones por usuario
                    //MigrateSession -- migra la sesion anterior
                    // sf.newSession(); // Crea una nueva sesion
                    // sf.none(); //No hace nada
                    sm.maximumSessions(1);

                    //MigrateSession -- migra la sesion anterior
                    // sf.newSession(); // Crea una nueva sesion
                    // sf.none(); //No hace nada
                    sm.sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::migrateSession);

                    //Info sobre la sesion creada por el usuario
                    sm.sessionConcurrency(concurrency->{
                        concurrency.sessionRegistry(sessionRegistry());

                    });
                })
//                .httpBasic(httpBasic ->{
//                    httpBasic.
//                })//Autenticacion se envia en el header
                .build();
    }

    @Bean
    public SessionRegistry sessionRegistry(){
        return new SessionRegistryImpl();
    }

    public AuthenticationSuccessHandler successHandler(){
        return (((request, response, authentication) -> {
            response.sendRedirect(SecurityConstants.SESSION_PATH);
        }));
    }
}
