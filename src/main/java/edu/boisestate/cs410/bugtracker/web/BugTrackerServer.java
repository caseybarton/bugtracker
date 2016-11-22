package edu.boisestate.cs410.bugtracker.web;

import org.apache.commons.dbcp2.PoolingDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.*;
import spark.Request;
import spark.template.pebble.PebbleTemplateEngine;

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
        http.get("/bug/:bugid", this::redirectToFolder);
        http.get("/bug/:bugid/", this::bugPage, engine); //display bug info, tags, recent changes, comments, and field to add a comment
        http.get("/bug", this::redirectToFolder);
        http.get("/bug/", this::bugsPage, engine); //list all bugs
        http.get("/bug/:bugid/changelog", this::redirectToFolder);
        http.get("/bug/:bugid/changelog/", this::changelog, engine); //list entire changelog
        http.get("/createuser", this::redirectToFolder);
        http.get("/createuser/", this::createUserPage, engine);
        http.get("/edituser/:userid", this::redirectToFolder);
        http.get("/edituser/:userid/", this::editUserPage, engine);
        http.get("/submitbug", this::redirectToFolder);
        http.get("/submitbug/", this::submitBugPage, engine);
    }

    public String redirectToFolder(Request request, Response response) {
        String path = request.pathInfo();
        response.redirect(path + "/", 301);
        return "Redirecting to " + path + "/";
    }

    ModelAndView rootPage(Request request, Response response) throws SQLException {
        Map<String, java.lang.Object> fields = new HashMap<>();
        try (Connection cxn = pool.getConnection()) {
            fields.put("bugs", Bug.retrieveAssigned(cxn, userId));
            fields.put("bugChanges", BugChange.retrieveRecent(cxn, userId));
        }

        return new ModelAndView(fields, "base.html.twig");
    }

    //TODO everything

}