CREATE TABLE User_Account (
	user_id bigserial PRIMARY KEY NOT NULL,
	password_hash VARCHAR(255) NOT NULL,
	username TEXT,
	first_name TEXT,
	last_name TEXT,
	email VARCHAR(255)
);

CREATE TABLE Bug (
	bug_id bigserial PRIMARY KEY NOT NULL,
	details TEXT,
	close_time TIMESTAMP,
	status VARCHAR(255),
	title TEXT,
	creation_time TIMESTAMP,
	summary TEXT
);

CREATE TABLE Subscription (
	subscription_id bigserial PRIMARY KEY NOT NULL,
	bug_id bigint NOT NULL,
	user_id bigint NOT NULL
);

CREATE TABLE Bug_Submission (
	bug_submission_id bigserial PRIMARY KEY NOT NULL,
	bug_id bigint NOT NULL,
	user_id bigint NOT NULL
);

CREATE TABLE User_Assigned_Bug (
	user_assigned_bug_id bigserial PRIMARY KEY NOT NULL,
	user_id bigint NOT NULL,
	bug_id bigint NOT NULL
);

CREATE TABLE Bug_Change (
	bug_change_id bigserial PRIMARY KEY NOT NULL,
	creation_time TIMESTAMP,
	description VARCHAR(255),
	bug_id bigint NOT NULL,
	bug_details TEXT,
	bug_close_time TIMESTAMP,
	bug_status VARCHAR(255),
	bug_title TEXT,
	bug_summary TEXT
);


CREATE TABLE Bug_Comment (
	bug_comment_id bigserial PRIMARY KEY NOT NULL,
	content TEXT,
	creation_time TIMESTAMP,
	bug_id bigint NOT NULL,
	user_id bigint NOT NULL
);

CREATE TABLE Comment_Mentions_User (
	comment_mentions_user_id bigserial PRIMARY KEY NOT NULL,
	bug_comment_id bigint NOT NULL,
	user_id bigint NOT NULL
);

CREATE TABLE Tag (
	tag_title VARCHAR(255) PRIMARY KEY NOT NULL,
	description TEXT
);

CREATE TABLE Bug_Has_Tag (
	bug_has_tag_id bigserial PRIMARY KEY NOT NULL,
	bug_id bigint NOT NULL,
	tag_title VARCHAR(255) NOT NULL
);

ALTER TABLE Bug_Submission ADD FOREIGN KEY(bug_id) REFERENCES Bug;
ALTER TABLE Bug_Submission ADD FOREIGN KEY(user_id) REFERENCES User_Account;
ALTER TABLE Subscription ADD FOREIGN KEY(bug_id) REFERENCES Bug;
ALTER TABLE Subscription ADD FOREIGN KEY(user_id) REFERENCES User_Account;
ALTER TABLE User_Assigned_Bug ADD FOREIGN KEY(bug_id) REFERENCES Bug;
ALTER TABLE User_Assigned_Bug ADD FOREIGN KEY(user_id) REFERENCES User_Account;
ALTER TABLE Bug_Change ADD FOREIGN KEY(bug_id) REFERENCES Bug;
ALTER TABLE Bug_Comment ADD FOREIGN KEY(bug_id) REFERENCES Bug;
ALTER TABLE Bug_Comment ADD FOREIGN KEY(user_id) REFERENCES User_Account;
ALTER TABLE Bug_Has_Tag ADD FOREIGN KEY(bug_id) REFERENCES Bug;
ALTER TABLE Bug_Has_Tag ADD FOREIGN KEY(tag_title) REFERENCES Tag;
ALTER TABLE Comment_Mentions_User ADD FOREIGN KEY(bug_comment_id) REFERENCES Bug_Comment;
ALTER TABLE Comment_Mentions_User ADD FOREIGN KEY(user_id) REFERENCES User_Account;
