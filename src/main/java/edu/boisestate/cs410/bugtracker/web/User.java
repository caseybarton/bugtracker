package edu.boisestate.cs410.bugtracker.web;


import spark.Request;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * A user in the bug tracker system.
 */
public class User {
    private final long id;
    private final String username;
    private final String firstName;
    private final String lastName;
    private final String email;

    public User(long id, String username, String firstName, String lastName, String email) {
        this.id = id;
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
    }

    static public User getUser(Connection cxn, Long userId) throws SQLException {
        if (userId == null) {
            return null;
        }
        String userQuery = "SELECT * FROM user_account WHERE user_id = ?";

        PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new User(userId, rs.getString("username"), rs.getString("first_name"), rs.getString("last_name"), rs.getString("email"));
                } else {
                    return null;
                }
            }
        }
    }

    public long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getEmail() {
        return email;
    }
}