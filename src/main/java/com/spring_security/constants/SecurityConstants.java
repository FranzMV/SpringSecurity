package com.spring_security.constants;

import org.springframework.web.bind.annotation.*;

public class SecurityConstants {

    //ENDPOINT PATHS
    public static final String AUTH_PATH ="/auth";
    public static final String GET_PATH ="/auth/get";
    public static final String POST_PATH = "/auth/post";
    public static final String PUT_PATH = "/auth/put";
    public static final String DELETE_PATH = "/auth/delete";
    public static final String PATCH_PATH = "/auth/patch";

    //USER ROLES
    public static final String ADMIN_ROLE ="ADMIN";
    public static final String REFACTOR_ROLE ="REFACTOR";
    public static final String DEVELOPER_ROLE ="DEVELOPER";
    public static final String USER_ROLE ="USER";
    public static final String INVITED_ROLE ="INVITED";

    //CONF JWT
    public static final String ROLE_ ="ROLE_";
    public static final String AUTHORITIES ="authorities";
}
