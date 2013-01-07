# Authlite - A Simple Authentication module for Kohana

 * Authlite is a simple and lightweight authentication module based on the official Kohana _Auth_ module. It is compatible with _Auth_ and does not force the concept of `roles`.
 * Added the possibility of remembering various logins (using a separate table to hold the cookie values)
 * If you change the `username` column in config, you have to change it on both tables (`users.username` and `logins.username`)
 * Log last login date and IP address

## MySQL structure

<pre><code>
CREATE TABLE IF NOT EXISTS `users` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `password` char(64) NOT NULL,
  `name` varchar(30) NOT NULL,
  `email` varchar(150) NOT NULL,
  `ip` varchar(15) DEFAULT NULL,
  `last_login` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `logins` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `token` varchar(127) DEFAULT NULL,
  `date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `username` (`username`,`date`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;
</code></pre>

## Notes

The "k2" branch and 1.x tags are for Kohana 2.3. The "master" branch and 2.x tags are for Kohana 3.0.

Authlite 2.0 in the master branch is in beta.

Added branch 3.3/develop
