package com.spring_security.DTO;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

public record AuthCreateUserRequest(@NotBlank String username, @NotBlank String password, @Valid AuthCreateRoleRequest roleRequest) {
}
