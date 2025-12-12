package com.instagram.identity.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Represents a user role inside MongoDB.
 *
 * Examples:
 *  - ROLE_ADMIN
 *  - ROLE_BUYER
 *  - ROLE_SELLER
 *
 * Roles are assigned to users and used by Spring Security
 * to determine access rights.
 */
@Data
@Document(collection = "roles")
public class Role {

    @Id
    private String id; // MongoDB unique role ID

    private String name; // name of the role (e.g., ROLE_ADMIN)
}
