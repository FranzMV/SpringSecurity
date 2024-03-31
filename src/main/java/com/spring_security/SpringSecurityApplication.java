package com.spring_security;

import com.spring_security.persistence.entity.PermissionEntity;
import com.spring_security.persistence.entity.RoleEntity;
import com.spring_security.persistence.entity.RoleEnum;
import com.spring_security.persistence.entity.UserEntity;
import com.spring_security.persistence.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.util.Set;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Bean
	CommandLineRunner init(UserRepository userRepository){
		return args -> {
			//CREATE PERMISSIONS
			PermissionEntity createPermission = PermissionEntity
					.builder()
					.name("CREATE")
					.build();

			PermissionEntity readPermission = PermissionEntity
					.builder()
					.name("READ")
					.build();

			PermissionEntity updatePermission = PermissionEntity
					.builder()
					.name("UPDATE")
					.build();

			PermissionEntity deletePermission = PermissionEntity
					.builder()
					.name("DELETE")
					.build();

			PermissionEntity refactorPermission = PermissionEntity
					.builder()
					.name("REFACTOR")
					.build();

			//CREATE ROLES
			RoleEntity roleAdmin = RoleEntity
					.builder()
					.roleEnum(RoleEnum.ADMIN)
					.permissionEntitySet(Set.of(createPermission, readPermission, updatePermission, deletePermission))
					.build();

			RoleEntity roleUser = RoleEntity
					.builder()
					.roleEnum(RoleEnum.USER)
					.permissionEntitySet(Set.of(createPermission, readPermission))
					.build();

			RoleEntity roleInvited = RoleEntity
					.builder()
					.roleEnum(RoleEnum.INVITED)
					.permissionEntitySet(Set.of(createPermission))
					.build();

			RoleEntity roleDeveloper = RoleEntity
					.builder()
					.roleEnum(RoleEnum.DEVELOPER)
					.permissionEntitySet(Set.of(createPermission, readPermission, updatePermission, deletePermission,refactorPermission))
					.build();

			//CREATE USERS
			UserEntity userSantiago = UserEntity
					.builder()
					.username("santiago")
					.password("$2a$10$G42uXPX0zFCqsnY9astldOB3jloKULwdMKQ1gLbg.BXRORg6Adztm")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialsNoExpired(true)
					.roles(Set.of(roleAdmin))
					.build();

			UserEntity userDaniel = UserEntity
					.builder()
					.username("daniel")
					.password("$2a$10$G42uXPX0zFCqsnY9astldOB3jloKULwdMKQ1gLbg.BXRORg6Adztm")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialsNoExpired(true)
					.roles(Set.of(roleUser))
					.build();

			UserEntity userAndrea = UserEntity
					.builder()
					.username("andrea")
					.password("$2a$10$G42uXPX0zFCqsnY9astldOB3jloKULwdMKQ1gLbg.BXRORg6Adztm")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialsNoExpired(true)
					.roles(Set.of(roleInvited))
					.build();

			UserEntity userFran = UserEntity
					.builder()
					.username("fran")
					.password("$2a$10$G42uXPX0zFCqsnY9astldOB3jloKULwdMKQ1gLbg.BXRORg6Adztm")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialsNoExpired(true)
					.roles(Set.of(roleDeveloper))
					.build();

			userRepository.saveAll(List.of(userSantiago,userDaniel,userAndrea, userFran));
		};
	}
}
