package edu.boisestate.cs410.bugtracker.web;

import org.apache.commons.dbcp2.PoolingDataSource;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.*;
import spark.Request;
import spark.template.pebble.PebbleTemplateEngine;

import java.security.SecureRandom;
import java.sql.*;
import java.util.*;

/**
 * Server for the bug tracker database.
 */
public class BugTrackerServer {
    private static final Logger logger = LoggerFactory.getLogger(BugTrackerServer.class);

    private final PoolingDataSource<? extends Connection> pool;
    private final Service http;
    private final TemplateEngine engine;

    public BugTrackerServer(PoolingDataSource<? extends Connection> pds, Service svc) {
        pool = pds;
        http = svc;
        engine = new PebbleTemplateEngine();

        http.get("/", this::rootPage, engine); //user homepage with assigned bugs, most recent subbed-bug changes, and links to edit account info and submit new bug
        http.get("/logout", this::logout);
        http.post("/login", this::login);
        http.post("/createUser", this::createUser);
        http.post("/editUser", this::editUser);
        http.post("/submitBug", this::submitBug);
//        http.get("/bug/:bugID/comment", this::redirectToFolder);
//        http.get("/bug/:bugID/comment", this::addComment, engine); //simply a handler for submitted comments. will insert the comment and redirect back to the bugid page
        http.get("/bug/:bugID", this::redirectToFolder);
        http.get("/bug/:bugID/", this::bugIDPage, engine); //display bug info, tags, recent changes, comments, and field to add a comment
        http.get("/bug", this::redirectToFolder);
        http.get("/bug/", this::bugsPage, engine); //list all bugs
//        http.get("/bug/:bugid/changelog", this::redirectToFolder);
//        http.get("/bug/:bugid/changelog/", this::changelog, engine); //list entire changelog
        http.get("/login", this::redirectToFolder);
        http.get("/login/", this::loginPage, engine);
        http.get("/createUser", this::redirectToFolder);
        http.get("/createUser/", this::createUserPage, engine);
        http.get("/editUser", this::redirectToFolder);
        http.get("/editUser/", this::editUserPage, engine);
        http.get("/submitBug", this::redirectToFolder);
        http.get("/submitBug/", this::submitBugPage, engine);
    }

/*  TODO Implement the above methods with the following code at the beginning of each one */

    //Redirect if not logged in
    void checkSession(Request request, Response response) throws SQLException {
        User user;
        Long userId = request.session().attribute("userId");
        try (Connection cxn = pool.getConnection()) {
            user = User.getUser(cxn, userId);
        }
        if (user == null) {
            response.redirect("/login/", 303);
        }
    }


    public String redirectToFolder(Request request, Response response) {
        String path = request.pathInfo();
        response.redirect(path + "/", 301);
        return "Redirecting to " + path + "/";
    }



    ModelAndView rootPage(Request request, Response response) throws SQLException {
        Map<String, java.lang.Object> fields = new HashMap<>();
        User user;
        Long userId = request.session().attribute("userId");
        try (Connection cxn = pool.getConnection()) {
            user = User.getUser(cxn, userId);
            if(user != null) {
                fields.put("user", user);
                fields.put("bugs", Bug.retrieveAssigned(cxn, userId));
                fields.put("bugChanges", BugChange.retrieveRecentChangesOfUserSubscriptions(cxn, userId));
            }
        }

        if(user == null){
            response.redirect("/login/", 303);
        }

        // initialize CSRF token
        String token = request.session().attribute("csrf_token");
        if (token == null) {
            SecureRandom rng = new SecureRandom();
            byte[] bytes = new byte[8];
            rng.nextBytes(bytes);
            token = Base64.getEncoder().encodeToString(bytes);
            request.session(true).attribute("csrf_token", token);
        }
        fields.put("csrf_token", token);

        return new ModelAndView(fields, "home.html.twig");
    }

    String logout(Request request, Response response) {
        request.session().removeAttribute("userId");
        response.redirect("/", 303);
        return "Goodbye";
    }

    String login(Request request, Response response) throws SQLException {
        String name = request.queryParams("username");
        if (name == null || name.isEmpty()) {
            http.halt(400, "No user name provided");
        }
        String password = request.queryParams("password");
        if (password == null || password.isEmpty()) {
            http.halt(400, "No password provided");
        }

        String userQuery = "SELECT user_id, password_hash FROM user_account WHERE username = ?";

        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
            stmt.setString(1, name);
            logger.debug("looking up user {}", name);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    logger.debug("found user {}", name);
                    String hash = rs.getString("password_hash");
                    if (BCrypt.checkpw(password, hash)) {
                        logger.debug("user {} has valid password", name);
                        request.session(true).attribute("userId", rs.getLong("user_id"));
                        response.redirect("/", 303);
                        return "Hi!";
                    } else {
                        logger.debug("invalid password for user {}", name);
                    }
                } else {
                    logger.debug("no user {} found", name);
                }
            }
        }

        http.halt(400, "invalid username or password");
        return null;
    }

    String createUser(Request request, Response response) throws SQLException {
        String name = request.queryParams("username");
        if (name == null || name.isEmpty()) {
            http.halt(400, "No user name provided");
        }
        String password = request.queryParams("password");
        if (password == null || password.isEmpty()) {
            http.halt(400, "No password provided");
        }
        if (!password.equals(request.queryParams("confirm"))) {
            http.halt(400, "Password and confirmation do not match.");
        }
        String pwHash = BCrypt.hashpw(password, BCrypt.gensalt(10));
        String first_name = request.queryParams("first_name");
        String last_name = request.queryParams("last_name");
        String email = request.queryParams("email");

        //verify username not taken
        String checkUsername = "SELECT user_id FROM user_account WHERE username = ?";
        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(checkUsername)) {
            stmt.setString(1, name);
            stmt.execute();
            try (ResultSet rs = stmt.getResultSet()) {
                if(rs.next()) {
                    long returnedUserId = rs.getLong(1);
                    logger.info("username {} already exists with id {}", name, returnedUserId);
                    http.halt(400, "Username taken");
                }
            }
        }


        String addUser = "INSERT INTO user_account (username, password_hash, first_name, last_name, email) " +
                "VALUES (?, ?, ?, ?, ?) " +
                "RETURNING user_id"; // PostgreSQL extension

        long userId;

        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(addUser)) {
            stmt.setString(1, name);
            stmt.setString(2, pwHash);
            stmt.setString(3, first_name);
            stmt.setString(4, last_name);
            stmt.setString(5, email);
            stmt.execute();
            try (ResultSet rs = stmt.getResultSet()) {
                rs.next();
                userId = rs.getLong(1);
                logger.info("added user {} with id {}", name, userId);
            }
        }

        Session session = request.session(true);
        session.attribute("userId", userId);

        response.redirect("/", 303);
        return "See you later!";
    }

    String editUser(Request request, Response response) throws SQLException {
//        long userId = new Long(request.queryParams("user_id")).longValue();
        //validate token
        String token = request.session().attribute("csrf_token");
        String submittedToken = request.queryParams("csrf_token");
        if (token == null || !token.equals(submittedToken)) {
            http.halt(400, "invalid CSRF token");
        }

        //get field info
        String userId = request.queryParams("user_id");
        String first_name = request.queryParams("first_name");
        String last_name = request.queryParams("last_name");
        String email = request.queryParams("email");


        //if password fields aren't empty and are valid, update password, else leave password alone
        String newPassword = request.queryParams("new_password");
        if (newPassword != null && !newPassword.isEmpty()) {
            String currentPassword = request.queryParams("current_password");
            if (currentPassword == null || currentPassword.isEmpty()) {
                http.halt(400, "current password must be provided in order to change password");
            }

            String userQuery = "SELECT password_hash FROM user_account WHERE user_id = ?";

            try (Connection cxn = pool.getConnection();
                 PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
                stmt.setLong(1, new Long(userId).longValue());
                logger.debug("looking up user {}", userId);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        logger.debug("found user {}", userId);
                        String hash = rs.getString("password_hash");
                        if (BCrypt.checkpw(currentPassword, hash)) {
                            logger.debug("user {} has valid password", userId);
                            String pwHash = BCrypt.hashpw(newPassword, BCrypt.gensalt(10));
                            PreparedStatement stmt2 = cxn.prepareStatement("UPDATE user_account SET password_hash = ? WHERE user_id = ? RETURNING user_id");
                            stmt2.setString(1, pwHash);
                            stmt2.setLong(2, new Long(userId).longValue());
                            try (ResultSet rs2 = stmt2.executeQuery()) {
                                if (rs2.next()) {
                                    logger.debug("successfully updated user {} password", userId);
                                } else {
                                    logger.debug("failed to update password for user {}", userId);
                                }
                            }
                        } else {
                            logger.debug("invalid password for user {}", userId);
                            http.halt(400, "invalid password");
                        }
                    } else {
                        logger.debug("no user {} found", userId);
                    }
                }
            }
        }


        //edit user info
        String addUser = "UPDATE user_account SET (first_name, last_name, email) = (?, ?, ?) \n" +
                "WHERE user_id = ? \n" +
                "RETURNING user_id"; // PostgreSQL extension

        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(addUser)) {
            stmt.setString(1, first_name);
            stmt.setString(2, last_name);
            stmt.setString(3, email);
            stmt.setLong(4, new Long(userId).longValue());
            stmt.execute();
            try (ResultSet rs = stmt.getResultSet()) {
                if(rs.next()) {
                    logger.info("updated user {} with id {}", userId);
                }else{
                    logger.info("failed to update user {}", userId);
                }
            }
        }

        response.redirect("/", 303);
        return "User account updated!";
    }

    String submitBug(Request request, Response response) throws SQLException {
        String token = request.session().attribute("csrf_token");
        String submittedToken = request.params("csrf_token");
        if (token == null || !token.equals(submittedToken)) {
            http.halt(400, "invalid CSRF token");
        }

        //get field info
        String title = request.queryParams("title");
        String details = request.queryParams("details");
        String summary = request.queryParams("summary");

        //edit user info
        String addBug = "INSERT INTO Bug (title, details, status, creation_time, summary) " +
                "VALUES (?, ?, ?, ?, ?) " +
                "RETURNING bug_id"; // PostgreSQL extension

        try (Connection cxn = pool.getConnection();
            PreparedStatement stmt = cxn.prepareStatement(addBug)) {
            stmt.setString(1, title);
            stmt.setString(2, details);
            stmt.setString(3, "new"); // All bugs start with status "new"
            stmt.setTimestamp(4, new Timestamp(System.currentTimeMillis()));
            stmt.setString(5, summary);
            stmt.execute();

            ResultSet rs = stmt.getResultSet();
            rs.next();
            long bugId = rs.getLong(1);
            logger.info("added bug with title {}, id {}", title, bugId);
        }

        response.redirect("/", 303);
        return "Bug submitted!";
    }

    ModelAndView loginPage(Request request, Response response) throws SQLException {
        Map<String,Object> fields = new HashMap<>();
        return new ModelAndView(fields, "login.html.twig");
    }

    ModelAndView createUserPage(Request request, Response response) throws SQLException {
        Map<String, java.lang.Object> fields = new HashMap<>();
        return new ModelAndView(fields, "createUser.html.twig");
    }

    ModelAndView editUserPage(Request request, Response response) throws SQLException {
        Map<String, java.lang.Object> fields = new HashMap<>();
        User user;
        Long userId = request.session().attribute("userId");
        try (Connection cxn = pool.getConnection()) {
            user = User.getUser(cxn, userId);
            if(user != null) {
                fields.put("user", user);
            }
        }
        if(user == null){
            response.redirect("/login/", 303);
        }

        String token = request.session().attribute("csrf_token");
        fields.put("csrf_token", token);

        return new ModelAndView(fields, "editUser.html.twig");
    }

    ModelAndView submitBugPage(Request request, Response response) throws SQLException {
        Map<String, java.lang.Object> fields = new HashMap<>();

        User user;
        Long userId = request.session().attribute("userId");
        try (Connection cxn = pool.getConnection()) {
            user = User.getUser(cxn, userId);
            if(user != null) {
                fields.put("user", user);
            }
        }
        if(user == null){
            response.redirect("/login/", 303);
        }

        String token = request.session().attribute("csrf_token");
        fields.put("csrf_token", token);

        return new ModelAndView(fields, "submitBug.html.twig");
    }

    ModelAndView bugsPage(Request request, Response response) throws SQLException {
        checkSession(request, response);
        Map<String, java.lang.Object> fields = new HashMap<>();

        //List all bugs, most recent first
        String bugsQuery = "SELECT bug_id, title, creation_time, summary, status \n" +
                "FROM bug\n" +
                "ORDER BY creation_time DESC;";
        try (Connection cxn = pool.getConnection()) {
             try (PreparedStatement stmt = cxn.prepareStatement(bugsQuery)) {
                 try (ResultSet rs = stmt.executeQuery()) {
                     if (rs.next()) {
                         List<Map<String, Object>> bugs = new ArrayList<>();

                         //Record first row. We jumped ahead one row by checking if the query had no results
                         Map<String, Object> bug = new HashMap<>();
                         bug.put("id", rs.getLong("bug_id"));
                         bug.put("title", rs.getString("title"));
                         bug.put("creation_time", rs.getTimestamp("creation_time"));
                         bug.put("summary", rs.getString("summary"));
                         bug.put("status", rs.getString("status"));
                         bugs.add(bug);

                         while (rs.next()) {
                             bug = new HashMap<>();
                             bug.put("id", rs.getLong("bug_id"));
                             bug.put("title", rs.getString("title"));
                             bug.put("creation_time", rs.getTimestamp("creation_time"));
                             bug.put("summary", rs.getString("summary"));
                             bug.put("status", rs.getString("status"));
                             bugs.add(bug);
                         }
                         fields.put("bugs", bugs);
                     }
                 }
             }
        }
        return new ModelAndView(fields, "bug.html.twig");
    }

    ModelAndView bugIDPage(Request request, Response response) throws SQLException {
        checkSession(request, response);
        Map<String, java.lang.Object> fields = new HashMap<>();
        Integer bugID = Integer.parseInt(request.params("bugID"));
        fields.put("bugID", bugID);

        //display bug info, tags, recent changes, comments, and field to add a comment
        try (Connection cxn = pool.getConnection()) {
            //Get bug info
            String bugQuery = "SELECT * FROM bug WHERE bug_id = ?;";
            try (PreparedStatement stmt = cxn.prepareStatement(bugQuery)) {
                stmt.setInt(1, bugID);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        fields.put("id", rs.getLong("bug_id"));
                        fields.put("details", rs.getLong("details"));
                        fields.put("title", rs.getString("title"));
                        fields.put("creation_time", rs.getTimestamp("creation_time"));
                        fields.put("close_time", rs.getTimestamp("close_time"));
                        fields.put("summary", rs.getString("summary"));
                        fields.put("status", rs.getString("status"));
                    }
                    else {
                        logger.debug("failed to get bug {}. does not exist", bugID);
                        http.halt(400, "Bug #"+bugID+" does not exist");
                    }
                }
            }

            //Get tags for bug
            String tagsQuery = "SELECT tag_title, description\n" +
                    "FROM tag \n" +
                    "JOIN bug_has_tag USING (tag_title)\n" +
                    "JOIN bug USING (bug_id)\n" +
                    "WHERE bug_id = ?;";
            try (PreparedStatement stmt = cxn.prepareStatement(tagsQuery)) {
                stmt.setInt(1, bugID);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        List<Map<String, Object>> tags = new ArrayList<>();

                        Map<String, Object> tag = new HashMap<>();
                        tag.put("title", rs.getString("tag_title"));
                        tags.add(tag);
                        while(rs.next()) {
                            tag = new HashMap<>();
                            tag.put("title", rs.getString("tag_title"));
                            tags.add(tag);
                        }
                        fields.put("tags", tags);
                    }
                    else {
                        logger.debug("no tags were found for bug #{}", bugID);
                    }
                }
            }

            //Get users assigned to this bug
            String assigneeQuery = "SELECT user_id, email\n" +
                    "FROM bug\n" +
                    "JOIN user_assigned_bug USING (bug_id)\n" +
                    "JOIN user_account USING (user_id)\n" +
                    "WHERE bug_id = ?;";
            try (PreparedStatement stmt = cxn.prepareStatement(assigneeQuery)) {
                stmt.setInt(1, bugID);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        List<Map<String, Object>> assignees = new ArrayList<>();

                        Map<String, Object> assignee = new HashMap<>();
                        assignee.put("assignedUser", rs.getLong("email"));
                        assignees.add(assignee);
                        while(rs.next()) {
                            assignee = new HashMap<>();
                            assignee.put("assignedUser", rs.getLong("email"));
                            assignees.add(assignee);
                        }
                        fields.put("assignedUsers", assignees);
                    }
                    else {
                        logger.debug("failed to get bug {}. does not exist", bugID);
                        http.halt(400, "Bug #"+bugID+" does not exist");
                    }
                }
            }

            //Get most recent bug change
            String changeQuery = "SELECT bug_change_id, bug_change.creation_time, description\n" +
                    "FROM bug_change\n" +
                    "JOIN bug USING (bug_id)\n" +
                    "WHERE bug_id = ?\n" +
                    "ORDER BY bug_change.creation_time DESC\n" +
                    "LIMIT 1;";
            try (PreparedStatement stmt = cxn.prepareStatement(changeQuery)) {
                stmt.setInt(1, bugID);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        fields.put("change_id", rs.getLong("bug_change_id"));
                        fields.put("change_description", rs.getLong("description"));
                        fields.put("change_creation_time", rs.getTimestamp("bug_change.creation_time"));
                    }
                    else {
                        fields.put("no_changes", true);
                        logger.debug("no recent changes for bug #{}", bugID);
                    }
                }
            }

            //Get all comments for this bug
            String commentsQuery = "SELECT content, bug_comment.creation_time, email AS author\n" +
                    "FROM bug\n" +
                    "JOIN bug_comment USING (bug_id)\n" +
                    "JOIN user_account USING (user_id)\n" +
                    "WHERE bug_id = ?\n" +
                    "ORDER BY bug_comment.creation_time DESC;";
            try (PreparedStatement stmt = cxn.prepareStatement(commentsQuery)) {
                stmt.setInt(1, bugID);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        List<Map<String, Object>> comments = new ArrayList<>();

                        Map<String, Object> comment = new HashMap<>();
                        comment.put("creation_time", rs.getLong("bug_comment.creation_time"));
                        comment.put("author", rs.getLong("author"));
                        comment.put("content", rs.getLong("content"));
                        comments.add(comment);
                        while(rs.next()) {
                            comment = new HashMap<>();
                            comment.put("creation_time", rs.getLong("bug_comment.creation_time"));
                            comment.put("author", rs.getLong("author"));
                            comment.put("content", rs.getLong("content"));
                            comments.add(comment);
                        }
                        fields.put("comments", comments);
                    }
                    else {
                        fields.put("no_comments", true);
                        logger.debug("no comments for bug #{}", bugID);
                    }
                }
            }
        }

        return new ModelAndView(fields, "bugID.html.twig");
    }
}

