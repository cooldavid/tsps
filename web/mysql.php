<?php
	include_once("config.php");
	$dblink = mysql_connect($mysql_server, $mysql_user, $mysql_pass);
	if (!$dblink)
		die("Unable to connect to database");

	if (!mysql_select_db($mysql_db, $dblink) &&
	    !mysql_create_db($mysql_db, $dblink))
		die("Unable to select to database");

	mysql_query("CREATE TABLE IF NOT EXISTS `users` (
		`id` BIGINT NOT NULL AUTO_INCREMENT,
                `user` varchar(32) NOT NULL default '',
                `pass` varchar(64) NOT NULL default '',
                `email` varchar(128) NOT NULL default '',
                `lastlogin` timestamp NOT NULL default '00:00:00',
                `state` tinyint(20) NOT NULL default '0',
		AUTO_INCREMENT = 16,
		PRIMARY KEY (`id`),
		KEY `user` (`user`),
		KEY `email` (`email`)
	) TYPE=MyISAM;", $dblink);

	function entry_is_unique($col, $value) {
		global $dblink;
		$rc = false;

		$res = mysql_query("SELECT `$col` FROM `users` WHERE `$col`='$value'",$dblink);
		if (!$res)
			return false;

		if (mysql_num_rows($res) == 0)
			$rc = true;
		mysql_free_result($res);
		return $rc;
	}

	function loginid_is_unique($loginid) {
		return entry_is_unique("user", $loginid);
	}

	function email_is_unique($email) {
		return entry_is_unique("email", $email);
	}

	function create_user($loginid, $email) {
		$active_code = hash("sha256", $loginid.$email.microtime());

		$res = mysql_query("INSERT INTO `users` SET
			`user` = '$loginid',
			`pass` = '$active_code',
			`email` = '$email',
			`lastlogin` = CURRENT_TIMESTAMP(),
			`state` = 0;");
		return $active_code;
	}

	function get_active_key($loginid) {
		global $dblink;
		$ak = "";

		$res = mysql_query("SELECT `pass` FROM `users` WHERE `user`='$loginid' AND `state`=0",$dblink);
		if (!$res)
			return "";
		if (mysql_num_rows($res) != 1)
			$ak = "";
		$row = mysql_fetch_assoc($res);
		$ak = $row['pass'];
		mysql_free_result($res);
		return $ak;
	}

	function get_email($loginid) {
		global $dblink;
		$email = "";

		$res = mysql_query("SELECT `email` FROM `users` WHERE `user`='$loginid' AND `state`=1",$dblink);
		if (!$res)
			return "";
		if (mysql_num_rows($res) != 1)
			$email = "";
		$row = mysql_fetch_assoc($res);
		$email = $row['email'];
		mysql_free_result($res);
		return $email;
	}

	function get_user($email) {
		global $dblink;
		$user = "";

		$res = mysql_query("SELECT `user` FROM `users` WHERE `email`='$email' AND `state`=0",$dblink);
		if (!$res)
			return "";
		if (mysql_num_rows($res) != 1)
			$user = "";
		$row = mysql_fetch_assoc($res);
		$user = $row['user'];
		mysql_free_result($res);
		return $user;
	}

	function update_password($loginid, $password) {
		global $dblink;

		$hashed_pass = md5($loginid.":cdpatsps:".$password);
		mysql_query("UPDATE `users` SET `pass`='$hashed_pass',`state`=1 WHERE `user`='$loginid'",$dblink);
	}
?>
