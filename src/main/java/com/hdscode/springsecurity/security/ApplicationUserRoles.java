package com.hdscode.springsecurity.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.hdscode.springsecurity.security.ApplicationUserPermission.*;

public enum ApplicationUserRoles {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_WRITE, COURSE_READ, STUDENT_WRITE, STUDENT_READ));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRoles(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }
}
