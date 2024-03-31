package com.spring_security.service;

import com.spring_security.constants.SecurityConstants;
import com.spring_security.persistence.entity.UserEntity;
import com.spring_security.persistence.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

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
}
