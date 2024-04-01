package com.spring_security.service;

import com.spring_security.DTO.AuthLoginRequest;
import com.spring_security.DTO.AuthResponse;
import com.spring_security.constants.SecurityConstants;
import com.spring_security.persistence.entity.UserEntity;
import com.spring_security.persistence.repository.UserRepository;
import com.spring_security.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserRepository userRepository;

    /**
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findUserEntityByUsername(username)
                        .orElseThrow(()-> new UsernameNotFoundException("El usuario "+ username+" no existe"));

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        userEntity.getRoles()
                .forEach(role -> authorityList.add
                        (new SimpleGrantedAuthority(SecurityConstants.ROLE_.concat(role.getRoleEnum().name()))));

        userEntity.getRoles().stream()
                .flatMap(role -> role.getPermissionEntitySet().stream())
                .forEach(permission -> authorityList.add(new SimpleGrantedAuthority(permission.getName())));

        return new User
                (
                    userEntity.getUsername(),
                    userEntity.getPassword(),
                    userEntity.isEnabled(),
                    userEntity.isAccountNoExpired(),
                    userEntity.isCredentialsNoExpired(),
                    userEntity.isAccountNoLocked(),
                    authorityList
                );
    }

    /**
     * Genera el token de acceso
     * @param authLoginRequest authLoginRequest
     * @return AuthResponse authResponse
     */
    public AuthResponse loginUser(AuthLoginRequest authLoginRequest){
        //Recuperamos el user y el password que viene en el parametro AuthLoginRequest
        String username = authLoginRequest.username();
        String password = authLoginRequest.password();

        Authentication authentication = this.authenticate(username, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = jwtUtils.createToken(authentication);

        return new AuthResponse(username, "User logged successfully", accessToken, true);
    }

    private Authentication authenticate(String username, String password){
        UserDetails userDetails = this.loadUserByUsername(username);
        if(userDetails == null){
            throw new BadCredentialsException("Invalid username or password");
        }
        if(!passwordEncoder.matches(password,userDetails.getPassword())){
            throw new BadCredentialsException("Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());
    }
}
