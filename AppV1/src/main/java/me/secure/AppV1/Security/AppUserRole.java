package me.secure.AppV1.Security;

import static me.secure.AppV1.Security.AppUserPermission.COURSE_READ;
import static me.secure.AppV1.Security.AppUserPermission.COURSE_WRITE;
import static me.secure.AppV1.Security.AppUserPermission.STUDENT_READ;
import static me.secure.AppV1.Security.AppUserPermission.STUDENT_WRITE;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.google.common.collect.Sets;

public enum AppUserRole {
	// Google guava dependency properties
	STUDENT(Sets.newHashSet()),
	ADMIN(Sets.newHashSet(COURSE_READ,COURSE_WRITE,STUDENT_READ,STUDENT_WRITE)),
	ADMINTRAINEE(Sets.newHashSet(COURSE_READ,STUDENT_READ));

	private final Set<AppUserPermission> permissions;

	private AppUserRole(Set<AppUserPermission> permissions) {
		this.permissions = permissions;
	}

	public Set<AppUserPermission> getPermissions() {
		return permissions;
	}

	public Set<GrantedAuthority> getGrantedAuthorities() {
		Set<GrantedAuthority> permissions =	getPermissions().stream()
			.map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
			.collect(Collectors.toSet());

		permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
		return permissions;
	}
}
