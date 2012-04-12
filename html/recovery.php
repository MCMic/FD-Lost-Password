<?php
require_once("../include/php_setup.inc");
require_once("functions.inc");
require_once("variables.inc");

function displayPWchanger()
{
  global $smarty;

  $smarty->display(get_template_path('recovery.tpl'));
  exit();
}

function loadConfig()
{
  global $_SERVER;

  /* Check if CONFIG_FILE is accessible */
  if (!is_readable(CONFIG_DIR."/".CONFIG_FILE)) {
    msg_dialog::display(_("Fatal error"),
                        sprintf(_("FusionDirectory configuration %s/%s is not readable. Aborted."),
                                CONFIG_DIR, CONFIG_FILE), FATAL_ERROR_DIALOG);
    exit();
  }

  /* Parse configuration file */
  $config = new config(CONFIG_DIR."/".CONFIG_FILE, $BASE_DIR);
  session::global_set('DEBUGLEVEL', $config->get_cfg_value("debuglevel"));
  if ($_SERVER["REQUEST_METHOD"] != "POST") {
    @DEBUG(DEBUG_CONFIG, __LINE__, __FUNCTION__, __FILE__, $config->data,
           "config");
  }
  return $config;
}

function setupLanguage()
{
  global $config,$GLOBALS,$BASE_DIR;

  /* Language setup */
  if ($config->get_cfg_value("language") == "") {
    $lang = get_browser_language();
  } else {
    $lang = $config->get_cfg_value("language");
  }

  $lang .= ".UTF-8";
  putenv("LANGUAGE=");
  putenv("LANG=$lang");
  setlocale(LC_ALL, $lang);
  $GLOBALS['t_language'] = $lang;
  $GLOBALS['t_gettext_message_dir'] = $BASE_DIR.'/locale/';

  /* Set the text domain as 'messages' */
  $domain = 'messages';
  bindtextdomain($domain, LOCALE_DIR);
  textdomain($domain);
}

function setupSmarty()
{
  global $config, $smarty;

  /* Set template compile directory */
  $smarty->compile_dir = $config->get_cfg_value("templateCompileDirectory", SPOOL_DIR);

  /* Check for compile directory */
  if (!(is_dir($smarty->compile_dir) && is_writable($smarty->compile_dir))) {
    msg_dialog::display(_("Configuration error"),
                        sprintf(_("Directory '%s' specified as compile directory is not accessible!"),
                                $smarty->compile_dir),
                        FATAL_ERROR_DIALOG);
    exit();
  }

  /* Check for old files in compile directory */
  clean_smarty_compile_dir($smarty->compile_dir);
}

function generateRandomHash()
{
  /* Generate a very long random value */
  $len = 56;
  $base = 'ABCDEFGHKLMNOPQRSTWXYZabcdefghjkmnpqrstwxyz123456789';
  $max = strlen($base) - 1;
  $randomhash = '';
  mt_srand((double) microtime() * 1000000);
  while (strlen($randomhash) < $len + 1)
    $randomhash .= $base{mt_rand(0, $max)};
  return $randomhash;
}

function storeTempPassword($temp_password)
{
  global $config, $address_mail, $delay_allowed;

  /* Store it in a ldap with the salt */
  $salt_temp_password = $salt.$temp_password.$salt;
  $sha1_temp_password = sha1($salt_temp_password);

  /* Store sha1(unique_id) in the sambaLMPassword attribut => the LM hash isn't needed for anything newer then Windows 95. */

  $ldap = $config->get_ldap_link();

  $ldap->search("(&(objectClass=gosaMailAccount)(mail=".$address_mail.
                ")(uid=".$uid."))", array("dn"));
  $attrs = $ldap->fetch();

  /* This check is a little bit weird */
  if (count($attrs) != 2) {
    return _("There is a problem with your account, check parameters !");
  }

  $dn = $attrs['dn'];

  $ldap->cd($dn);

  $attrs = array();
  $attrs['sambaLMPassword'] = $sha1_temp_password;
  /* Value stocked is the maximum allowed value */
  $attrs['sambaPwdLastSet'] = time() + $delay_allowed;

  $ldap->modify($attrs);

  if (!$ldap->success()) {
    return msgPool::ldaperror($ldap->get_error(),
                              $dn,
                              LDAP_MOD, ERROR_DIALOG);
  }

  return "";
}

function step3()
{
  global $uid, $address_mail, $from_mail, $smarty, $message;
  /* Send a mail, save information in session and create a very random unique id */

  $activatecode = generateRandomHash();

  $error = storeTempPassword($activatecode);

  if (!empty($error)) {
    msg_dialog::display(_("LDAP error"), $error);
  } else {
    $reinit_link = "https://elledap1.ibcp.fr/fusiondirectory/recovery.php"; //FIXME
    $reinit_link .= "?uniq=".$activatecode;
    $reinit_link .= "&uid=".$uid;
    $reinit_link .= "&address_mail=".$address_mail;

    /* Send the mail */
    $mail_body = "Bonjour,\n\n";
    $mail_body .= "Voici les informations necessaire : \n";
    $mail_body .= " - Votre login : ".$uid."\n";
    $mail_body .= " - Liens de reinitialisation : ".$reinit_link;
    $mail_body .= "\n\n";
    $mail_body .= "Attention, ce lien est valide durant 10 minutes.";
    $mail_body .= "\n\n";
    $mail_body .= "Le service informatique.";

    /* From */
    $headers = "From: ".$from_mail."\r\n";
    $headers .= "Reply-To: ".$from_mail."\r\n";

    if (mail($address_mail, "[CNRS IBCP]: liens de réinitialisation", $mail_body, $headers)) {
      $smarty->assign("step3", true);
    } else {
      $message[] = msgPool::invalid(_("Contact your administrator : check your mail serveur"));
    }
  }
}

if (!class_exists("log")) {//FIXME : should not be necessary
  require_once("class_log.inc");
}

header("Content-type: text/html; charset=UTF-8");

session::start();

/* Some Configuration variable */

/* Salt needed to mask the uniq id in the ldap */
$salt = "phrasetreslongueetcompliquequidoitrestersecrete";
/* Verbose */
$debug = 0;
/* Allow locked account with an valide end date to activate ? */
$activate = 1;
/* IPs allowed to recovery */
/* => Treated by the webserver */
$ip = "";
/* Delay allowed for the user to change his password */
$delay_allowed = 600;

/* Sender */
$from_mail = "tobechanged@domain.fr";

/* Destroy old session if exists.
    Else you will get your old session back, if you not logged out correctly. */
if (is_array(session::get_all()) && count(session::get_all())) {
  session::destroy();
  session::start();
}

/* Reset errors */
session::global_set('js', true);
reset_errors();

$config = loadConfig();

setupSmarty();

setupLanguage();

/* Generate server list */
$servers = array();
foreach ($config->data['LOCATIONS'] as $key => $ignored) {
  $servers[$key] = $key;
}

if (isset($_POST['server'])) {
  $directory = validate($_POST['server']);
} else {
  $directory = $config->data['MAIN']['DEFAULT'];

  if (!isset($servers[$directory])) {
    $directory = key($servers);
  }
}

if (isset($_GET['directory']) && isset($servers[$_GET['directory']])) {
  $smarty->assign("show_directory_chooser", false);
  $directory = validate($_GET['directory']);
} else {
  $smarty->assign("show_directory_chooser", false);//FIXME
  $smarty->assign("server_options", $servers);
  $smarty->assign("server_id", $directory);
}

/* Set config to selected one */
$config->set_current($directory);
session::global_set('config', $config);

if ($_SERVER["REQUEST_METHOD"] != "POST") {//FIXME
  @DEBUG(DEBUG_TRACE, __LINE__, __FUNCTION__, __FILE__, $lang,
         "Setting language to");
}

/* Check for SSL connection */
$ssl = "";
if (!isset($_SERVER['HTTPS']) || !stristr($_SERVER['HTTPS'], "on")) {
  if (empty($_SERVER['REQUEST_URI'])) {
    $ssl = "https://".$_SERVER['HTTP_HOST'].$_SERVER['PATH_INFO'];
  } else {
    $ssl = "https://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
  }
}

/* If SSL is forced, just forward to the SSL enabled site */
if ($config->get_cfg_value("forcessl") == 'true' && $ssl != '') {
  header("Location: $ssl"); //FIXME : line 84 already sent header
  exit;
}

/* Check for selected password method */
$method = $config->get_cfg_value("passwordDefaultHash", "crypt/md5");
if (isset($_GET['method'])) {
  $method = validate($_GET['method']);
  $tmp = new passwordMethod($config);
  $available = $tmp->get_available_methods();
  if (!isset($available[$method])) {
    msg_dialog::display(_("Password method"),
                        _("Error: Password method not available!"),
                        FATAL_ERROR_DIALOG);
    exit();
  }
}

if (isset($_GET['address_mail']) && $_GET['address_mail'] != "") {
  $address_mail = validate($_GET['address_mail']);
  $smarty->assign('address_mail', $address_mail);
} elseif(isset($_POST['address_mail'])) {
  $address_mail = validate($_POST['address_mail']);
  $smarty->assign('address_mail', $address_mail);
}

/* Check for selected user... */
if (isset($_GET['uid']) && $_GET['uid'] != "") {
  $uid = validate($_GET['uid']);
  $smarty->assign('display_username', false);
} elseif(isset($_POST['uid'])) {
  $uid = validate($_POST['uid']);
  $smarty->assign('display_username', true);
} else {
  $uid = "";
  $smarty->assign('display_username', true);
}

$current_password = "";

$smarty->assign('uid', $uid);
$smarty->assign("step1", true);
$smarty->assign("step2", false);
$smarty->assign("step3", false);
$smarty->assign("step4", false);
$smarty->assign("step5", false);

/* Got a formular answer, validate and try to log in */
/*if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['apply']))*/
if ($_SERVER["REQUEST_METHOD"] == "POST") {

  $message = array();

  /* Destroy old sessions, they cause a successfull login to relog again ... */
  if (session::global_is_set('_LAST_PAGE_REQUEST')) {
    session::global_set('_LAST_PAGE_REQUEST', time());
  }

  if (isset($_POST['send'])) {
    step3();
    /* Send a mail, save information in session and create a very random unique id */
  } elseif(isset($_POST['change'])) {
    /* Some rapid Check */
    $uniq_id_from_mail = validate($_GET['uniq']); //FIXME : GET?

    $temp_uniq_id = $salt.$uniq_id_from_mail.$salt;
    $uniq_id = sha1($temp_uniq_id);

    /* Retrieve hash from the ldap */
    $ldap = $config->get_ldap_link();

    $ldap->search("(&(objectClass=gosaMailAccount)(mail=".$address_mail.
                  ")(uid=".$uid."))", array("sambaLMPassword",
                                            "sambaPwdLastSet", "dn"));
    $attrs = $ldap->fetch();

    $ldap_uniq_id = $attrs['sambaLMPassword'][0];
    $last_time_recovery = $attrs['sambaPwdLastSet'][0];
    $dn = $attrs['dn'];

/*        echo "LDAP uniq : ".$ldap_uniq_id."<br/>";
        echo "Last Time Recovery : ".$last_time_recovery."<br/>";
        echo "Time : ".time()."<br/>";
        echo "Strlen : ".strlen($ldap_uniq_id)."<br/>";
  echo "DN : ".$dn."<br/>";*/

    $now = time();
    /* Same test as previous step */

    if ((strlen($ldap_uniq_id) == 40) and($last_time_recovery >=
                                          $now) and(strcmp($uniq_id,
                                                           $ldap_uniq_id) ==
                                                    0)) {
      $uniq = $uniq_id_from_mail;
      $smarty->assign("step4", true);
      $smarty->assign('uniq', $uniq_id_from_mail);
      $step = 4;

      if ($config->get_cfg_value("passwordMinDiffer") != "")
        $MinDiffer = $config->get_cfg_value("passwordMinDiffer");
      else
        $MinDiffer = 0;

      if ($config->get_cfg_value("passwordMinLength") != "")
        $MinLength = $config->get_cfg_value("passwordMinLength");
      else
        $MinLength = 0;

      /* Do new and repeated password fields match? */
      $new_password = $_POST['new_password'];
      if ($_POST['new_password'] != $_POST['new_password_repeated']) {
        $message[] =
          _
          ("The passwords you've entered as 'New password' and 'Repeated new password' do not match.");
      } elseif ($_POST['new_password'] == "") {
        $message[] = msgPool::required(_("New password"));
      }
      /* Password policy fulfilled? */
      elseif (($MinDiffer > 0)
               and(substr($_POST['current_password'], 0, $l) ==
                   substr($_POST['new_password'], 0, $l))) {
        $message[] =
          _("The password used as new and current are too similar.");
      } elseif (strlen($_POST['new_password']) < $MinLength)
        $message[] = _("The password used as new is to short.");

      /* IT SEEM THAT CODE IS NOT NEED ! Q&A need to read carefully next lines !!
         /* Validate
         if (!tests::is_uid($uid)){
         $message[]= msgPool::invalid(_("Login"));
         } elseif (mb_strlen($_POST["current_password"], 'UTF-8') == 0){
         $message[]= msgPool::required(_("Current password"));
         } else {

         /* Do we have the selected user somewhere?
         $ui= ldap_login_user ($uid, $current_password);

         if ($ui === NULL){
         $message[]= _("Please check the username/password combination.");
         } else {
         $acls = $ui->get_permissions($ui->dn,"users/password");
         if(!preg_match("/w/i",$acls)){
         $message[]= _("You have no permissions to change your password.");
         }
         }
         }
       */

      else {
        /* Passed quality check, just try to change the password now */
        $output = "";
        if ($config->get_cfg_value("passwordHook") != "") {
          exec($config->get_cfg_value("passwordHook")." ".
               escapeshellarg($_POST['new_password']), $resarr);
          if (count($resarr) > 0) {
            $output = join('\n', $resarr);
          }
        }
        if ($output != "") {
          $message[] =
            _("External password changer reported a problem: ".$output);
          msg_dialog::displayChecks($message);
        } else {
          if ($method != "") {
            change_password($dn, $_POST['new_password'], 0, $method);
          } else {
            change_password($dn, $_POST['new_password']);
          }
          gosa_log("User/password has been changed");
          /* Send the mail */
          $message = "Bonjour,\n\n";
          $message .=
            "Le mot de passe de votre compte vient d'etre change. : \n\n";
          $message .= "Pour rappel voici votre login : ".$uid."\n";
          $message .= "\n\n";
          $message .= "Le service informatique.";

          /* From */
          $headers = "From: ".$from_mail."\r\n";
          $headers .= "Reply-To: ".$from_mail."\r\n";

          if (mail
              ($address_mail,
               "[CNRS IBCP]: Confirmation changement de mot de passe",
               $message, $headers)) {
            gosa_log("User/password has been changed");
            /* TODO a new function */
            /*      $message[]= msgPool::invalid(_("User/password has been changed !")); */
            $smarty->assign("step4", false);
            $step = 5;
            $smarty->assign("changed", true);
          }
        }
      }
    } else {
      /* TODO a new function */
      $message[] = msgPool::invalid(_(".... BAD !"));
    }
  } else {
    /* Ask for the method */
    if ($_POST['address_mail'] == "") {
      $message[] = msgPool::required(_("Adresse mail"));
    } else {
      $address_mail = $_POST['address_mail'];

      /*  echo $address_mail; */
      /* Search uid corresponding to the mail */
      /* TODO : regarder pour utiliser get_list */
      $uids =
        get_sub_list("(&(objectClass=gosaMailAccount)(mail=".$address_mail.
                     "))", "", array(get_ou("people")),
                     $config->current['BASE'], array("uid"),
                     GL_SUBSEARCH | GL_NO_ACL_CHECK);
      /*print_r($uids); */

      /* Un seul uid pour le mail given */
      /*echo count($uids); */
      if (count($uids) == 1) {
        $uid = $uids[0]['uid'][0];
        $dn = $uids[0]['dn'][0];
        $smarty->assign("step2", true);
        $smarty->assign("address_mail", $address_mail);
        $step = 2;
      } else {
        $message[] = msgPool::invalid(_("Mail"));
      }
    }
  }

}

if ($_SERVER["REQUEST_METHOD"] == "GET") {
  if (isset($_GET['uniq'])) {
/*  echo "Step 4<br/>";*/

    $smarty->assign('uid', $uid);

    /* Get the uniq */
    $uniq_id_from_mail = validate($_GET['uniq']);

    $smarty->assign('uniq', $uniq_id_from_mail);

    $temp_uniq_id = $salt.$uniq_id_from_mail.$salt;
    $uniq_id = sha1($temp_uniq_id);

/*        echo "Temp_password : ".$temp_uniq_id."<br/>";
        echo "sha1 => Temp_password : ".sha1($temp_uniq_id)."<br/>";*/

    /* Retrieve hash from the ldap */
    $ldap = $config->get_ldap_link();

    $ldap->search("(&(objectClass=gosaMailAccount)(mail=".$address_mail.
                  ")(uid=".$uid."))", array("sambaLMPassword",
                                            "sambaPwdLastSet"));
    $attrs = $ldap->fetch();

    $ldap_uniq_id = $attrs['sambaLMPassword'][0];
    $last_time_recovery = $attrs['sambaPwdLastSet'][0];

/*  echo "LDAP uniq : ".$ldap_uniq_id."<br/>";
  echo "Last Time Recovery : ".$last_time_recovery."<br/>";
  echo "Time : ".time()."<br/>";
  echo "Strlen : ".strlen($ldap_uniq_id)."<br/>"; */

    /* Length of the value, has the user really ask for a new password ? */
    if (strlen($ldap_uniq_id) == 40) {
      $now = time();
      /* Time between the request and the action need to be inferior to delay */
      if ($last_time_recovery >= $now) {
        /* a == b ? */
        if ((strcmp($uniq_id, $ldap_uniq_id) == 0)) {
/*        echo "ok<br/>";*/
          $smarty->assign("step4", true);
          $uniq = $uniq_id_from_mail;
          $step = 4;
        } else {
          /* Need to be cleaned by the creation of a real function to display error message */
          $message[] =
            msgPool::
            invalid(_("Check your link or restart from the beginning !"));
          $smarty->assign("step1", true);
/*        echo "nok<br/>";*/
        }
      } else {
        $message[] =
          msgPool::
          invalid(_
                  ("You take too much time between the request and the click on the link !"));
        $smarty->assign("step1", true);
/*    echo "nok<br/>";    */
      }
    } else {
      /* Need to be cleaned by the creation of a real function to display error message */
      $message[] =
        msgPool::invalid(_("This e-mail never ask for a new password !"));
      $smarty->assign("step1", true);
/*      echo "nok<br/>";*/
    }

  }
}
/*&& isset($_POST['apply']))*/

/* Do we need to show error messages? */
if (count($message) != 0) {
  /* Show error message and continue editing */
  msg_dialog::displayChecks($message);
}

/* Parameter fill up */
$params = "";
/* Not necessary now */
/*echo $address_mail;*/

if (($step == 2) or($step == 4)) {
  foreach(array('uid', 'method', 'directory', 'address_mail', 'uniq') as
          $index) {
    $params .= "&amp;$index=".urlencode($$index);
  }
  $params = preg_replace('/^&amp;/', '?', $params);
/*    echo $params; */
  $smarty->assign('params', $params);

  /* Fill template with required values */
  $smarty->assign('date', gmdate("D, d M Y H:i:s"));
  $smarty->assign('uid', $uid);
  $smarty->assign('password_img', get_template_path('images/password.png'));
}

/* Displasy SSL mode warning? */
if ($ssl != "" && $config->get_cfg_value("warnssl") == 'true') {
  $smarty->assign("ssl",
                  "<b>"._("Warning").":</b> ".
                  _("Session will not be encrypted.").
                  " <a style=\"color:red;\" href=\"".htmlentities($ssl).
                  "\"><b>"._("Enter SSL session")."</b></a>!");
} else {
  $smarty->assign("ssl", "");
}

/* show login screen */
$smarty->assign("JS", session::global_get('js'));
$smarty->assign("PHPSESSID", session_id());
if (session::is_set('errors')) {
  $smarty->assign("errors", session::get('errors'));;
}
if ($error_collector != "") {
  $smarty->assign("php_errors", $error_collector."</div>");
} else {
  $smarty->assign("php_errors", "");
}

$smarty->assign("msg_dialogs", msg_dialog::get_dialogs());
displayPWchanger();

?></body > </html >
// vim:tabstop=2:expandtab:shiftwidth=2:filetype=php:syntax:ruler:
