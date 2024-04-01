package com.spring_security.service;

import com.spring_security.DTO.AuthCreateUserRequest;
import com.spring_security.DTO.AuthLoginRequest;
import com.spring_security.DTO.AuthResponse;
import com.spring_security.constants.SecurityConstants;
import com.spring_security.persistence.entity.RoleEntity;
import com.spring_security.persistence.entity.UserEntity;
import com.spring_security.persistence.repository.RoleRepository;
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;

    /**
     * Busca los usuarios en la Base de datos, obtiene los roles y permisos
     * @param username username
     * @return UserDetails
     * @throws UsernameNotFoundException UsernameNotFoundException
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
     *  Login de usuario y genera el token de acceso
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



    /**
     * Valida el username y password del user
     * @param username username
     * @param password password
     * @return UsernamePasswordAuthenticationToken
     */
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


    /**
     * Creacion de un nuevo usuario
     * @param authCreateUserRequest authCreateUserRequest
     * @return AuthResponse
     */
    public AuthResponse createUser(AuthCreateUserRequest authCreateUserRequest){
        String username = authCreateUserRequest.username();
        String password = authCreateUserRequest.password();
        List<String> roleRequest = authCreateUserRequest.roleRequest().roleListName();

        //Obtenemos los roles existentes en la Base de datos
        Set<RoleEntity> roleEntitySet = new HashSet<>(roleRepository.findRoleEntitiesByRoleEnumIn(roleRequest));
        if(roleEntitySet.isEmpty()){
            throw new IllegalArgumentException("The roles specified does not exist.");
        }
        //Seteamos un nuevo usuario
        UserEntity userEntity = UserEntity.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .roles(roleEntitySet)
                .isEnabled(true)
                .accountNoLocked(true)
                .accountNoExpired(true)
                .credentialsNoExpired(true)
                .build();

        //Lo guardamos en la base de datos
        UserEntity userCreated = userRepository.save(userEntity);

        //Asignamos los roles
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();
        userCreated.getRoles().forEach(
                role -> authorityList.add(new SimpleGrantedAuthority(SecurityConstants.ROLE_.concat(role.getRoleEnum().name())))
        );
        //Asignamos los permisos
        userCreated.getRoles()
                .stream()
                .flatMap(role -> role.getPermissionEntitySet().stream())
                .forEach(permissions -> authorityList.add(new SimpleGrantedAuthority(permissions.getName())));

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userCreated.getUsername(),
                userCreated.getPassword(),
                authorityList
        );

        //Generamos el token
        String accessToken =jwtUtils.createToken(authentication);

        return new AuthResponse(userCreated.getUsername(), "User created successfully", accessToken, true);
    }
}
