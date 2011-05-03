<?php
if (!isset($_GET['ak']) ||
    preg_match("/^[0-9a-f]{64}$/", $_GET['ak']) == 0 ||
    !isset($_GET['id']) ||
    preg_match("/^[0-9a-zA-Z]{3,32}$/", $_GET['id']) == 0) {
        header("Location: https://".$_SERVER['SERVER_NAME']."/");
}
$activate_key = $_GET['ak'];
$loginid = $_GET['id'];
include_once("mysql.php");
include_once("email.php");
include_once("function.php");
?><!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
<title>Activate account -- Gateway6 HTTP Server</title>
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

        $saved_activate_key = get_active_key($loginid);
        if (strcmp($saved_activate_key, $activate_key)) {
                errmsg("Activation key error");
        }

        if (!$have_error) {
                $password = generate_password();
                update_password($loginid, $password);
                echo "Your password is: $password<br>\n";
                if (send_password_email($loginid, get_email($loginid), $password))
                        echo "Password has been sent to your E-Mail";
                else
                        errmsg("Fail to deliver password E-Mail");
        }
?>
</body>
</html>
