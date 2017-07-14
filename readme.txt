=== No User Enumeration ===
Contributors: cmontiers
Donate link: #
Tags: User Enumeration, Security, WPSCAN, WordPress Vulnerability Scanner
Requires at least: 2.9
Tested up to: 4.7
Stable tag: 1.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Stop user enumeration for security.
== Description ==
In many WordPress installations is possible enumerate usernames through the author archives, using urls like this:

http://wpsite/?author=1

http://wpsite/?author=1/

http://wpsite/?bypass=1&author%00=1

http://wpsite/?author%00=%001

http://wpsite/?%61uthor=1

And recently wordpress 4.7 comes with a rest api integrated that allow list users:

curl -s http://wpsite/wp-json/wp/v2/users/

Know the username of a administrator is the half battle, now an attacker only need guest the password.
This plugin stop it.

Also, is possible get usernames from the post entries.
This plugin, hide the name of the author in a post entry if he is not using a nickname.
Also, hide the url page link of an administrator author.

The main goal is hide the administrators usernames.
Obviously, is better not choose "admin" as the username because is easiliy guessable.

== Installation ==

1. Upload `no-user-enumeration` to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress

== Frequently asked questions ==
.

== Screenshots ==
.

== Changelog ==
= 1.2 =
+ Disallow list users using the rest api.
* Compatibility with plugin WP All Import.
= 1.1 =
* Hide admin usernames in post replies. Improved security.
= 1.0 =
* First version.

== Upgrade Notice ==
.
