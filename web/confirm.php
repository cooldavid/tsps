<?php
$reqfrom = "https://".$_SERVER['SERVER_NAME']."/create.php";
if (strcmp($_SERVER['HTTP_REFERER'], $reqfrom) ||
    strcmp($_SERVER['REQUEST_METHOD'], "POST")) {
	    header("Location: $reqfrom");
}

session_name('numimg');
session_start();
include_once("mysql.php");
include_once("email.php");
?><!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
<title>Confirm account creation -- Gateway6 HTTP Server</title>
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
</head>

<body>
<?php
	$have_error = false;
	function errmsg($msg)
	{
		global $have_error;
		echo "<font color=\"red\">$msg</font><br>\n";
		$have_error = true;
	}

	if (!isset($_POST['loginid']) || !isset($_POST['email'])) {
		errmsg("Must specify Login-ID and E-Mail.");
	}
	$loginid = $_POST['loginid'];
	$email = $_POST['email'];

	if (strcmp($_SESSION['rndstr'], $_POST['numval'])) {
		errmsg("Confirm number is wrong. You are human, aren't you?");
	}

	if (preg_match("/^[0-9a-zA-Z]{3,32}$/", $loginid) == 0) {
		errmsg("Login-ID format error");
	}

	if (preg_match("/^[0-9a-zA-Z._-]+@[0-9a-zA-Z._-]+$/", $email) == 0) {
		errmsg("E-Mail address format error");
	}

	if (strlen($email) > 128) {
		errmsg("E-Mail address too long");
	}

	if (!loginid_is_unique($loginid)) {
		errmsg("User-ID has been taken");
	}

	if (!email_is_unique($email)) {
		errmsg("E-Mail already used by others");
	}

	if (!$have_error) {
		$active_code = create_user($loginid, $email);
		if (send_confirm_email($loginid, $email, $active_code))
			echo "Confirm E-Mail has been sent, please check your mailbox.";
		else
			errmsg("Fail to deliver confirm E-Mail");
	}
?>
</body>
</html>
