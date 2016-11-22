package edu.boisestate.cs410.bugtracker.web;


import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * A user in the bug tracker system.
 */
public class BugChange {
    private final long id;
    private final Timestamp creation_time;
    private final String description;

    public BugChange(long id, Timestamp creation_time, String description) {
        this.id = id;
        this.creation_time = creation_time;
        this.description = description;
    }

    static public List<BugChange> getRecentChangesOfUserSubscriptions(Connection cxn, Long userId) throws SQLException {
        List<BugChange> bugChanges = new ArrayList<>();

        if (userId == null) {return null;}

        String userQuery = "SELECT bug_change.* FROM bug_change \n" +
                "  JOIN bug USING (bug_id) \n" +
                "  JOIN subscription USING (bug_id)\n" +
                "WHERE user_id = ?\n" +
                "ORDER BY bug_change.creation_time DESC\n" +
                "LIMIT 10;";

        PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    bugChanges.add(new BugChange(rs.getLong("bug_change_id"), rs.getTimestamp("creation_time"), rs.getString("description")));
                }
            }
        }
        return bugChanges;
    }


    public long getId() {
        return id;
    }

    public Timestamp getCreationTime() {
        return creation_time;
    }

    public String getDescription() {
        return description;
    }
}