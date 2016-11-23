package edu.boisestate.cs410.bugtracker.web;


import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * A user in the bug tracker system.
 */
public class Bug {
    private final long id;
    private final String title;
    private final String summary;
    private final String details;
    private final String status;
    private final Timestamp close_time;
    private final Timestamp creation_time;


    public Bug(long id, String title, String summary, String details, String status, Timestamp close_time, Timestamp creation_time) {
        this.id = id;
        this.title = title;
        this.summary = summary;
        this.details = details;
        this.status = status;
        this.close_time = close_time;
        this.creation_time = creation_time;
    }

    static public List<Bug> retrieveAssigned(Connection cxn, Long userId) throws SQLException {
        List<Bug> bugs = new ArrayList<>();

        if (userId == null) {return null;}

        String userQuery = "SELECT * \n" +
                "FROM bug\n" +
                "JOIN user_assigned_bug USING (bug_id) \n" +
                "WHERE user_id = ?\n" +
                "ORDER BY creation_time DESC;";

        try(PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    bugs.add(new Bug(userId, rs.getString("title"), rs.getString("summary"), rs.getString("details"), rs.getString("status"), rs.getTimestamp("close_time"), rs.getTimestamp("creation_time")));
                }
            }
        }
        return bugs;
    }

    public long getId() {
        return id;
    }
    public String getTitle() {return title;}
    public String getSummary() {return summary;}
    public String getDetails() {return details;}
    public String getStatus() {return status;}
    public Timestamp getCloseTime() {return close_time;}
    public String getCloseTimeString() {return close_time.toString().substring(0,19);}
    public Timestamp getCreationTime() {return creation_time;}
    public String getCreationTimeString() {return creation_time.toString().substring(0,19);}
}