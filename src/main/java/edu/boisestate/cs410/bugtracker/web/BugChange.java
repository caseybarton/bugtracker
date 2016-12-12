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
    private final String bug_title;
    private final String bug_summary;
    private final String bug_details;
    private final String bug_status;
    private final Timestamp bug_close_time;


    public BugChange(long id, Timestamp creation_time, String description, String bug_title, String bug_summary, String bug_details, String bug_status, Timestamp bug_close_time) {
        this.id = id;
        this.creation_time = creation_time;
        this.description = description;
        this.bug_title = bug_title;
        this.bug_summary = bug_summary;
        this.bug_details = bug_details;
        this.bug_status = bug_status;
        this.bug_close_time = bug_close_time;
    }

    static public List<BugChange> retrieveRecentChangesOfUserSubscriptions(Connection cxn, Long userId) throws SQLException {
        List<BugChange> bugChanges = new ArrayList<>();

        if (userId == null) {return null;}

        String userQuery = "SELECT bug_change.* FROM bug_change \n" +
                "  JOIN bug USING (bug_id) \n" +
                "  JOIN subscription USING (bug_id)\n" +
                "WHERE subscription.user_id = ?\n" +
                "ORDER BY bug_change.creation_time DESC\n" +
                "LIMIT 10;";

        try(PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    bugChanges.add(new BugChange(rs.getLong("bug_change_id"),
                            rs.getTimestamp("creation_time"),
                            rs.getString("description"),
                            rs.getString("bug_title"),
                            rs.getString("bug_summary"),
                            rs.getString("bug_details"),
                            rs.getString("bug_status"),
                            rs.getTimestamp("bug_close_time")
                            ));
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
    public String getCreationTimeString() {
        return creation_time.toString().substring(0,19);    }
    public String getDescription() {
        return description;
    }
    public String getBugTitle() {
        return bug_title;
    }
    public String getBugSummary() {
        return bug_summary;
    }
    public String getBugDetails() {
        return bug_details;
    }
    public String getBugStatus() {
        return bug_status;
    }
    public Timestamp getBugCloseTime() {
        return bug_close_time;
    }
    public String getBugCloseTimeString() {
        return bug_close_time.toString().substring(0,19);
    }
}
