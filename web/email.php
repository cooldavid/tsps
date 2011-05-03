<?php
include_once("config.php");
function send_confirm_email($loginid, $email, $active_code)
{
	global $_SERVER;
	global $AdminEMail;
	global $ServerName;
	global $sendmail_path;

	$mail_body = "Please click on following link to activate your account:\n";
	$mail_body .= "https://".$_SERVER['SERVER_NAME']."/activate.php?id=$loginid&ak=$active_code\n";
	$subject = "CDPA Gateway6 Server: Confirm mail";
	$header = "From: ". $ServerName . " <" . $AdminEMail . ">\r\n";

	ini_set('sendmail_from', $AdminEMail);
	ini_set('sendmail_path', $sendmail_path);
	return mail($email, $subject, $mail_body);
}

function send_password_email($loginid, $email, $password)
{
	global $_SERVER;
	global $AdminEMail;
	global $ServerName;
	global $sendmail_path;

	$mail_body = "Welcome to $ServerName\n";
	$mail_body .= "Your Login-ID: $loginid\n";
	$mail_body .= "Your Password: $password\n";
	$subject = "CDPA Gateway6 Server: Password mail";
	$header = "From: ". $ServerName . " <" . $AdminEMail . ">\r\n";

	ini_set('sendmail_from', $AdminEMail);
	ini_set('sendmail_path', $sendmail_path);
	return mail($email, $subject, $mail_body);
}

?>
