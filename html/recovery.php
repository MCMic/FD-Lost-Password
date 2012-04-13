<?php

require_once("../include/php_setup.inc");
require_once("functions.inc");
require_once("variables.inc");

class passwordRecovery {
  var $config;
  var $uid;
  var $message = array();
  var $address_mail;
  var $method;
  var $directory;

  var $step = 1;

  /* Some Configuration variable */

  /* Salt needed to mask the uniq id in the ldap */
  var $salt = "phrasetreslongueetcompliquequidoitrestersecrete";
  /* Delay allowed for the user to change his password (minutes) */
  var $delay_allowed = 10;

  /* Sender */
  var $from_mail = "tobechanged@domain.fr";

  var $mail_body    = "";
  var $mail_subject = "";

  var $mail2_body     = "";
  var $mail2_subject  = "";

  /* Constructor */
  function passwordRecovery()
  {
    global $config;
    $this->mail_body = _("Hello,\n\nHere are your informations : \n - Login : %s\n - Link : %s\n\nThis link is ony valid for 10 minutes.");
    $this->mail_subject = _("[FusionDirectory] Password recovery link");
    $this->mail2_body = _("Hello,\n\nYour password has been changed.\nYour login is still %s\n");
    $this->mail2_subject = _("[FusionDirectory] Password recovery successful");

    /* Destroy old session if exists.
        Else you will get your old session back, if you not logged out correctly. */
    session::destroy();
    session::start();

    /* Reset errors */
    session::global_set('js', true);
    reset_errors();

    $this->config = $this->loadConfig();

    $this->readLdapConfig();

    $this->setupSmarty();

    $smarty = get_smarty();

    $this->setupLanguage();

    /* Generate server list */
    $servers = array();
    foreach ($this->config->data['LOCATIONS'] as $key => $ignored) {
      $servers[$key] = $key;
    }

    $smarty->assign("show_directory_chooser", false);

    if (isset($_POST['server'])) {
      $this->directory = validate($_POST['server']);
    } else {
      $this->directory = $this->config->data['MAIN']['DEFAULT'];

      if (!isset($servers[$this->directory])) {
        $this->directory = key($servers);
      }

      if (count($servers) > 1) {
        $smarty->assign("show_directory_chooser", true);
        $smarty->assign("server_options", $servers);
        $smarty->assign("server_id", $this->directory);
      }
    }

    if (isset($_GET['directory']) && isset($servers[$_GET['directory']])) {
      $this->directory = validate($_GET['directory']);
      $smarty->assign("show_directory_chooser", false);
    }

    /* Set config to selected one */
    $this->config->set_current($this->directory);
    session::global_set('config', $this->config);
    $config = $this->config;

    $ssl = $this->checkForSSL();

    /* Check for selected password method */
    $this->method = $this->config->get_cfg_value("passwordDefaultHash", "crypt/md5");
    if (isset($_GET['method'])) {
      $this->method = validate($_GET['method']);
      $tmp = new passwordMethod($this->config);
      $available = $tmp->get_available_methods();
      if (!isset($available[$this->method])) {
        msg_dialog::display(_("Password method"),
                            _("Error: Password method not available!"),
                            FATAL_ERROR_DIALOG);
        exit();
      }
    }

    if (isset($_GET['address_mail']) && $_GET['address_mail'] != "") {
      $this->address_mail = validate($_GET['address_mail']);
      $smarty->assign('address_mail', $this->address_mail);
    } elseif(isset($_POST['address_mail'])) {
      $this->address_mail = validate($_POST['address_mail']);
      $smarty->assign('address_mail', $this->address_mail);
    }

    /* Check for selected user... */
    if (isset($_GET['uid']) && $_GET['uid'] != "") {
      $this->uid = validate($_GET['uid']);
    } elseif(isset($_POST['uid'])) {
      $this->uid = validate($_POST['uid']);
    } else {
      $this->uid = "";
    }


  }

  function execute()
  {
    /* Got a formular answer, validate and try to log in */
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
      /* Destroy old sessions, they cause a successfull login to relog again ... */
      if (session::global_is_set('_LAST_PAGE_REQUEST')) {
        session::global_set('_LAST_PAGE_REQUEST', time());
      }

      if (isset($_POST['send'])) {
        $this->step3();
        /* Send a mail, save information in session and create a very random unique id */
      } elseif(isset($_POST['change'])) {
        $this->step4();
      } elseif(isset($_POST['apply'])) {
        $this->step2();
      }
    } elseif ($_SERVER["REQUEST_METHOD"] == "GET") {
      if (isset($_GET['uniq'])) {
        $this->step4();
      }
    }
  }

  function displayPWchanger()
  {
    global $error_collector, $error_collector_mailto;
    /* Do we need to show error messages? */
    if (count($this->message) != 0) {
      /* Show error message and continue editing */
      msg_dialog::displayChecks($this->message);
    }

    @DEBUG(DEBUG_TRACE, __LINE__, __FUNCTION__, __FILE__, $this->step,"Step");

    $smarty = get_smarty();

    $smarty->assign("JS", session::global_get('js'));
    $smarty->assign("PHPSESSID", session_id());
    if (session::is_set('errors')) {
      $smarty->assign("errors", session::get('errors'));
    }
    if ($error_collector != "") {
      $smarty->assign("php_errors", preg_replace("/%BUGBODY%/",$error_collector_mailto,$error_collector)."</div>");
    } else {
      $smarty->assign("php_errors", "");
    }

    $smarty->assign("msg_dialogs", msg_dialog::get_dialogs());
    $smarty->assign("usePrototype", "false");
    $smarty->display (get_template_path('headers.tpl'));

    $smarty->assign("version",FD_VERSION);
    $smarty->assign("step",$this->step);

    $smarty->display(get_template_path('recovery.tpl'));
    exit();
  }

  function loadConfig()
  {
    global $_SERVER, $BASE_DIR;

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
      @DEBUG(DEBUG_CONFIG, __LINE__, __FUNCTION__, __FILE__, $config->data, "config");
    }
    return $config;
  }

  /* Check that password recovery is activated, read config in ldap */
  function readLdapConfig()
  {
/*
    $this->salt           = ;
    $this->delay_allowed  = ;

    $this->mail_body      = ;
    $this->mail_subject   = ;
    $this->mail2_body     = ;
    $this->mail2_subject  = ;

    $this->from_mail      = ;
*/
  }

  function setupLanguage()
  {
    global $GLOBALS,$BASE_DIR;

    /* Language setup */
    if ($this->config->get_cfg_value("language") == "") {
      $lang = get_browser_language();
    } else {
      $lang = $this->config->get_cfg_value("language");
    }

    $lang .= ".UTF-8";
    putenv("LANGUAGE=");
    putenv("LANG=$lang");
    setlocale(LC_ALL, $lang);
    $GLOBALS['t_language'] = $lang;
    $GLOBALS['t_gettext_message_dir'] = $BASE_DIR.'/locale/';

    @DEBUG(DEBUG_TRACE, __LINE__, __FUNCTION__, __FILE__, $lang,"Setting language to");

    /* Set the text domain as 'messages' */
    $domain = 'messages';
    bindtextdomain($domain, LOCALE_DIR);
    textdomain($domain);
  }

  function setupSmarty()
  {
    $smarty = get_smarty();

    /* Set template compile directory */
    $smarty->compile_dir = $this->config->get_cfg_value("templateCompileDirectory", SPOOL_DIR);

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

    $smarty->assign('password_img', get_template_path('images/password.png'));
    $smarty->assign('date', gmdate("D, d M Y H:i:s"));
    $smarty->assign('params', "");
    $smarty->assign('message', "");
    $smarty->assign('changed', false);
    $smarty->assign('other_method', false);
  }

  static function generateRandomHash()
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

  function storeToken($temp_password)
  {
    /* Store it in ldap with the salt */
    $salt_temp_password = $this->salt.$temp_password.$this->salt;
    $sha1_temp_password = sha1($salt_temp_password);

    $ldap = $this->config->get_ldap_link();

    // Check if token branch is here
    $token = get_ou("tokenRDN").$this->config->current['BASE'];
    $ldap->cat($token, array('dn'));
    if (!$ldap->count()) {
      /* It's not, let's create it */
      $ldap->cd ($this->config->current['BASE']);
      $ldap->create_missing_trees($token);
      if (!$ldap->success()) {
        return msgPool::ldaperror($ldap->get_error(),
                                  $token, LDAP_MOD, get_class());
      }
      fusiondirectory_log("Created token branch ".$token);
    }

    $dn = "ou=".$this->uid.",$token";
    $ldap->cat($dn, array('dn'));
    $add = ($ldap->count() == 0);
    /* We store the token and its validity due date */
    $attrs = array(
                    'objectClass' => array('organizationalUnit'),
                    'ou' => $this->uid,
                    'userPassword' => $sha1_temp_password,
                    'description' => time() + $this->delay_allowed*60,
                  );
    $ldap->cd($dn);
    if ($add) {
      $ldap->add($attrs);
    } else {
      $ldap->modify($attrs);
    }

    if (!$ldap->success()) {
      return msgPool::ldaperror($ldap->get_error(),
                                $dn, LDAP_ADD, get_class());
    }

    return ""; /* Everything went well */
  }

  function checkToken($token)
  {
    $salt_token = $this->salt.$token.$this->salt;
    $sha1_token = sha1($salt_token);

    /* Retrieve hash from the ldap */
    $ldap = $this->config->get_ldap_link();

    $token = get_ou("tokenRDN").$this->config->current['BASE'];
    $dn = "ou=".$this->uid.",$token";
    $ldap->cat($dn);
    $attrs = $ldap->fetch();

    $ldap_token = $attrs['userPassword'][0];
    $last_time_recovery = $attrs['description'][0];

    /* Return true if the token match and is still valid */
    return ($last_time_recovery >= time()) &&
           ($ldap_token == $sha1_token);
  }

  function isValidPassword($new_password,$repeated_password)
  {
    //$MinDiffer = $this->config->get_cfg_value("passwordMinDiffer",0);
    $MinLength = $this->config->get_cfg_value("passwordMinLength",0);

    if ($new_password != $repeated_password) {
      return _("The passwords you've entered as 'New password' and 'Repeated new password' do not match.");
    } elseif ($new_password == "") {
      return msgPool::required(_("New password"));
    } elseif (strlen($new_password) < $MinLength) {
      return _("The password used as new is to short.");
    }
  }

  function checkForSSL()
  {
    $smarty = get_smarty();

    /* Check for SSL connection */
    $ssl = "";
    $smarty->assign("ssl", "");
    if (!isset($_SERVER['HTTPS']) || !stristr($_SERVER['HTTPS'], "on")) {
      if (empty($_SERVER['REQUEST_URI'])) {
        $ssl = "https://".$_SERVER['HTTP_HOST'].$_SERVER['PATH_INFO'];
      } else {
        $ssl = "https://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
      }

      /* If SSL is forced, just forward to the SSL enabled site */
      if ($this->config->get_cfg_value("forcessl") == 'true') {
        header("Location: $ssl");
        exit;
      } elseif ($this->config->get_cfg_value("warnssl") == 'true') {
        /* Display SSL mode warning? */
        $smarty->assign("ssl","<b>"._("Warning").":</b> ".
                        _("Session will not be encrypted.").
                        " <a style=\"color:red;\" href=\"".htmlentities($ssl).
                        "\"><b>"._("Enter SSL session")."</b></a>!");
      }
    }

    return $ssl;
  }

  function getPageURL()
  {
    $pageURL = "http";
    if (isset($_SERVER['HTTPS']) && ($_SERVER["HTTPS"] == "on")) {
      $pageURL .= "s";
    }
    $pageURL .= "://".$_SERVER["SERVER_NAME"];
    if ($_SERVER["SERVER_PORT"] != "80") {
      $pageURL .= ":".$_SERVER["SERVER_PORT"];
    }
/*
    $pageURL .= $_SERVER["REQUEST_URI"];
*/
    $pageURL .= $_SERVER["PHP_SELF"];

    return $pageURL;
  }

  function encodeParams($keys)
  {
    $params = "";
    foreach($keys as $key) {
      $params .= "&amp;$key=".urlencode($this->$key);
    }
    $params = preg_replace('/^&amp;/', '?', $params);
    return $params;
  }

  function getUserDn()
  {
    /* Retrieve dn from the ldap */
    $ldap = $this->config->get_ldap_link();

    $ldap->cd($this->config->current['BASE']);
    $ldap->search("(&(objectClass=gosaMailAccount)(uid=".$this->uid."))",array("dn"));

    if($ldap->count() < 1) {
      $this->message[] = sprintf(_("Did not found account %s"),$this->uid);
      return;
    } elseif ($ldap->count() > 1) {
      $this->message[] = sprintf(_("Found multiple accounts %s"),$this->uid);
      return;
    }

    $attrs = $ldap->fetch();

    return $attrs['dn'];
  }

  /* find the uid of for the given email address */
  function step2()
  {
    /* Ask for the method */
    if ($_POST['address_mail'] == "") {
      $this->message[] = msgPool::required(_("Adresse mail"));
      return;
    }
    $this->address_mail = $_POST['address_mail'];

    /* Search uid corresponding to the mail */
    $uids = get_list( "(&(objectClass=gosaMailAccount)(mail=".$this->address_mail."))",
                      "", $this->config->current['BASE'], array("uid"),
                      GL_SUBSEARCH | GL_NO_ACL_CHECK);

    /* Only one uid should be found */
    if (count($uids) < 1) {
      $this->message[] = sprintf(_("There is no account using email %s"),$this->address_mail);
      return;
    } elseif (count($uids) > 1) {
      $this->message[] = sprintf(_("There are several accounts using email %s"),$this->address_mail);
      return;
    }

    $smarty = get_smarty();

    $this->uid = $uids[0]['uid'][0];
    $smarty->assign('uid',$this->uid);
    $smarty->assign('address_mail', $this->address_mail);
    $this->step = 2;
    $params = $this->encodeParams(array('uid', 'method', 'directory', 'address_mail'));
    $smarty->assign('params', $params);
  }

  /* generate a token and send it by email */
  function step3()
  {
    $smarty = get_smarty();
    /* Send a mail, save information in session and create a very random unique id */

    $activatecode = $this->generateRandomHash();

    $error = $this->storeToken($activatecode);

    if (!empty($error)) {
      msg_dialog::display(_("LDAP error"), $error);
      return;
    }

    $reinit_link = $this->getPageURL();
    $reinit_link .= "?uniq=".$activatecode;
    $reinit_link .= "&uid=".$this->uid;
    $reinit_link .= "&address_mail=".$this->address_mail;

    @DEBUG(DEBUG_TRACE, __LINE__, __FUNCTION__, __FILE__, $reinit_link,"Setting link to");

    /* Send the mail */
    $mail_body = sprintf($this->mail_body,$this->uid,$reinit_link);

    /* From */
    $headers = "From: ".$this->from_mail."\r\n";
    $headers .= "Reply-To: ".$this->from_mail."\r\n";

    if (mail($this->address_mail, $this->mail_subject, $mail_body, $headers)) {
      $this->step = 3;
    } else {
      $this->message[] = msgPool::invalid(_("Contact your administrator, there was a problem with mail server"));
    }
    $smarty->assign('uid',$this->uid);
  }

  /* check if the given token is the good one */
  function step4()
  {
    $uniq_id_from_mail = validate($_GET['uniq']);

    if (!$this->checkToken($uniq_id_from_mail)) {
      $this->message[] = _("This token is invalid");
      return;
    }

    $smarty = get_smarty();

    $smarty->assign('uniq', $uniq_id_from_mail);
    $this->uniq = $uniq_id_from_mail;
    $this->step = 4;
    $smarty->assign('uid',$this->uid);
    $params = $this->encodeParams(array('uid', 'method', 'directory', 'address_mail', 'uniq'));
    $smarty->assign('params', $params);

    if(isset($_POST['change'])) {
      $this->step5();
    }
  }

  /* change the password and send confirmation email */
  function step5()
  {
    $dn = $this->getUserDn();
    if (!$dn) {
      return;
    }
    /* Do new and repeated password fields match? */
    $error = $this->isValidPassword( $_POST['new_password'],
                                     $_POST['new_password_repeated']);
    if (!empty($error)) {
      $this->message[] = $error;
      return;
    }

    /* Passed quality check, just try to change the password now */
    if ($this->config->get_cfg_value("passwordHook") != "") {
      exec($this->config->get_cfg_value("passwordHook")." ".
           escapeshellarg($_POST['new_password']), $resarr);
      if (count($resarr) > 0) {
        $this->message[] = _("External password changer reported a problem: ".join('\n', $resarr));
        msg_dialog::displayChecks($this->message);
        return;
      }
    }
    if ($this->method != "") {
      change_password($dn, $_POST['new_password'], 0, $this->method);
    } else {
      change_password($dn, $_POST['new_password']);
    }
    fusiondirectory_log("User ".$this->uid." password has been changed");
    /* Send the mail */
    $mail_body = sprintf($this->mail2_body,$this->uid);

    /* From */
    $headers = "From: ".$this->from_mail."\r\n";
    $headers .= "Reply-To: ".$this->from_mail."\r\n";


    if (mail($this->address_mail,$this->mail2_subject,$mail_body, $headers)) {
      $smarty = get_smarty();
      $this->step = 5;
      $smarty->assign('changed', true);
    }
  }

}

$pwRecovery = new passwordRecovery();

$pwRecovery->execute();

$pwRecovery->displayPWchanger();

?>
