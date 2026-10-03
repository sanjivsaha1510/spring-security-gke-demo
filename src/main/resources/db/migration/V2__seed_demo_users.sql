-- Demo users: alice / password (USER), bob / password (USER, ADMIN).
-- Hash is the same "{bcrypt}..." format DelegatingPasswordEncoder produces.
INSERT INTO app_user (username, password, enabled) VALUES
                                                       ('alice', '{bcrypt}$2a$10$W5rxJB5e6uw4aa5S5yN2vOAqiKco/Jo7pNV2C6FQJmjKWu9o.XZwa', TRUE),
                                                       ('bob',   '{bcrypt}$2a$10$W5rxJB5e6uw4aa5S5yN2vOAqiKco/Jo7pNV2C6FQJmjKWu9o.XZwa', TRUE);

INSERT INTO app_user_roles (user_id, role)
SELECT id, 'ROLE_USER' FROM app_user WHERE username IN ('alice', 'bob');

INSERT INTO app_user_roles (user_id, role)
SELECT id, 'ROLE_ADMIN' FROM app_user WHERE username = 'bob';