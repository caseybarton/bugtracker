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

        http.get("/", this::rootPage, engine); //login page; user homepage after logged in with assigned bugs, most recent subbed-bug changes, and links to edit account info and submit new bug
        http.get("/logout", this::logout);
        http.post("/login", this::login);
        http.post("/createUser", this::createUser);
        http.post("/editUser", this::editUser);
        http.get("/bug/:bugid", this::redirectToFolder);
        http.get("/bug/:bugid/", this::bugPage, engine); //display bug info, tags, recent changes, comments, and field to add a comment
        http.get("/bug", this::redirectToFolder);
        http.get("/bug/", this::bugsPage, engine); //list all bugs
        http.get("/bug/:bugid/changelog", this::redirectToFolder);
        http.get("/bug/:bugid/changelog/", this::changelog, engine); //list entire changelog
        http.get("/login", this::redirectToFolder);
        http.get("/login/", this::loginPage, engine);
        http.get("/createUser", this::redirectToFolder);
        http.get("/createUser/", this::createUserPage, engine);
        http.get("/editUser/:userid", this::redirectToFolder);
        http.get("/editUser/:userid/", this::editUserPage, engine);
        http.get("/submitBug", this::redirectToFolder);
        http.get("/submitBug/", this::submitBugPage, engine);
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
                fields.put("bugChanges", BugChange.retrieveRecent(cxn, userId));
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

        String addUser = "INSERT INTO bm_user (username, password_hash) " +
                "VALUES (?, ?) " +
                "RETURNING user_id"; // PostgreSQL extension

        long userId;

        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(addUser)) {
            stmt.setString(1, name);
            stmt.setString(2, pwHash);
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

    ModelAndView loginPage(Request request, Response response) throws SQLException {
        Map<String,Object> fields = new HashMap<>();
        return new ModelAndView(fields, "login.html.twig");
    }
}