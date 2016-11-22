# READ THIS

I've changed the logical schema a bit. You can see the changes in the google drive folder. The ddl there is obsolete, so use the one in the repo. 

I removed the newsfeed tables since they weren't really necessary for the project. I added fields to `bug_change` that correspond to all the fields in `bug`. I decided this was the simplest way to implement a changelog. Reverting to a previous change is just a matter of copying the `bug_change` fields back into `bug` including copying `bug_change.creation_date` into `bug.modified_date` and deleting all `bug_change` rows that occur later than this date. This means reverting to a previous change can't be undone, but allowing that just isn't worth the complexity.
`bug_change.description` should just contain a brief, programatically created description of what was changed.
