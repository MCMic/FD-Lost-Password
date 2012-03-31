<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
	"http://www.w3.org/TR/html4/transitional.dtd">
<html>
<!-- {debug} -->

<head>
  <title>FusionDirectory - {t}Recovery your password{/t}</title>

  <meta name="generator" content="my hands">
  <meta name="description" content="FusionDirectory - Password recovery">
  <meta name="author" lang="fr" content="">

  <meta http-equiv="Expires" content="Mon, 26 Jul 1997 05:00:00 GMT">
  <meta http-equiv="Last-Modified" content="{$date} GMT">
  <meta http-equiv="Cache-Control" content="no-cache">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Cache-Control" content="post-check=0, pre-check=0">
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

  <style type="text/css">@import url('themes/default/style.css');</style>
  <style type="text/css">@import url('themes/default/password-style.css');</style>
  <link rel="shortcut icon" href="favicon.ico">

  {if isset($ieworkaround)}<script language="javascript"src="include/png.js" type="text/javascript"></script>{/if}
  <script language="javascript" src="include/prototype.js" type="text/javascript"></script>
  <script language="javascript" src="include/fusiondirectory.js" type="text/javascript"></script>
  <script language="javascript" src="include/pwdStrength.js" type="text/javascript"></script>
</head>

<body style='height:100%; width:100%;'>
{* FusionDirectory recovery - smarty template *}
{$php_errors}

<form action='recovery.php{$params}' method='post' name='mainform' onSubmit='js_check(this);return true;'>
    <h1 class='headline'>
    <img class='center' src='images/password.png' alt='{t}Password{/t}' title='{t}Password{/t}'>
    {t}Lost password{/t}
    </h1>

    <!-- Display SSL warning message on demand -->
    <p class='warning'> {$ssl} </p>
    <input type='hidden' name='javascript' value='false'/>		

    <!-- Display error message on demand -->
    <p class='warning'> {$message} </p>

{if $step2}
    <p class="infotext">
    Aide relative au mot de passe pour le compte lié à l'adresse : {$address_mail}
    </p>

    <p class="infotext">
      M&eacute;thodes possibles :
     <ul>
      <li>Recevoir un lien de réinitialisation du mot de passe à votre adresse e-mail : 
	<input type='submit' name='send'  value='{t}Send{/t}'
               title='{t}Click here to send a reset link{/t}'>
	<input type='hidden' id='address_mail' maxlength='60' value='{$address_mail}'>
	<input type='hidden' id='uid' maxlength='60' value='{$uid}'>
      </li>
      {if $other_method}
      <li>
         L'option de récupération n'est pas possible ? Validez votre identité en répondant à plusieurs questions relatives à votre compte
      </li>
      <li>
	<font color="red">=>Contacter votre administrateur pour changer votre mot de passe.</font>
      </li>
      {/if}
     </ul>
    </p>
{elseif $other_metod}
    <p class="infotext">
    L'option de récupération n'est pas possible ? Validez votre identité en répondant à plusieurs questions relatives à votre compte
    {if !$other_method}
    <br/><font color="red">=> Cette option n'est pas active, veuillez contacter votre administrateur pour changer votre mot de passe.</font>
    </p>
    {/if}
{elseif $step3}
    <p class="infotext">
    La procedure pour réinitialiser le mot de passe pour a été envoyés à l'adresse {$address_mail}, check your mailbox.</br>
    <font color="red">Attention : ce lien n'est valide que 10 minutes.</font>
    </p>
{elseif $step4}
    <!-- Display SSL warning message on demand -->
    <p class='warning'> {$ssl} </p>
    <input type='hidden' name='javascript' value='false'/>

    <!-- Display error message on demand -->
    <p class='warning'> {$message} </p>


    <p class="infotext">
      {t}This dialog provides a simple way to change your password. Enter the new password (twice) in the fields below and press the 'Change' button.{/t}
    </p>

    <div class="ruler"></div>
    <table>
      {if $show_directory_chooser}
      <tr>
       <td>{t}Directory{/t}</td>
       <td>
          <select name='server'  title='{t}Directory{/t}'>
            {html_options options=$server_options selected=$server_id}
          </select>
	  </td>
      </tr>
      {/if}
      <tr>
       <td><label for='uid'>{t}Username{/t}</label></td>
       <td>{if $display_username}
           <input type='text' name='uid' id='uid' width='60' maxlength='60' value='{$uid}' title='{t}Username{/t}' onFocus="nextfield= 'current_password';">
           {else}
           <i>{$uid}</i>
           {/if}
       </td>
      </tr>
      <tr>
       <td><label for='new_password'>{t}New password{/t}</label></td>
       <td><input type='password' name='new_password' id="new_password" maxlength='40' value='' title='{t}New password{/t}' onFocus="nextfield= 'new_password_repeated';" onkeyup="testPasswordCss(document.getElementById('new_password').value);"></td>
      </tr>
      <tr>
       <td><label for='new_password_repeated'>{t}New password repeated{/t}</label></td>
       <td><input type='password' name='new_password_repeated' id='new_password_repeated' maxlength='40' value='' title='{t}New password repeated{/t}' onFocus="nextfield= 'apply';"></td>
      </tr>
      <tr>
       <td>{t}Password strength{/t}</td>
       <td>
        <span id="meterEmpty" style="padding:0;margin:0;width:100%;background-color:#DC143C;display:block;height:5px;">
        <span id="meterFull" style="padding:0;margin:0;z-index:100;width:0;background-color:#006400;display:block;height:5px;"></span></span>
       </td>
      </tr>
    </table>

    <div class="ruler"></div>

    <div class="change">                                                                                                                                        
      <input type='submit' name='change' value='{t}Change{/t}' title='{t}Click here to change your password{/t}'>
      <input type='hidden' id='address_mail' maxlength='60' value='{$address_mail}'>
      <input type='hidden' id='uniq' maxlength='60' value='{$uniq}'>
      <input type='hidden' id='formSubmit'>                                                                                                                       
    </div>
{elseif $changed}
<div class='success'">                                                                                                                                               
  <img class='center' src='images/true.png' alt='{t}Success{/t}' title='{t}Success{/t}'>&nbsp;<b>{t}Your password has been changed successfully.{/t}</b>                   
</div>
{else}
    <p class="infotext">
	{t}Enter your current e-mail address in the field below and press the 'Change' button.{/t}
	<br/>
	<strong>{t}=> Use your e-mail in the long format, e.g : John Doe => john.doe@ibcp.fr{/t}</strong>
    </p>

    <div class="ruler"></div>
    <table>
      {if $show_directory_chooser}
      <tr>
       <td>{t}Directory{/t}</td>
       <td>
          <select name='server'  title='{t}Directory{/t}'>
            {html_options options=$server_options selected=$server_id}
          </select>
        </td>
      </tr>
      {/if}
      <tr>
       <td><label for='mail'>{t}Adresse mail{/t}</label></td>
       <td>
           <input type='text' name='address_mail' id='address_mail' width='60' maxlength='60' value='{$address_mail}' title='{t}Mail{/t}' onFocus="">
       </td>
      </tr>
    </table>
    <div class="change">
    <input type='submit' name='apply'  value='{t}Change{/t}'
                 title='{t}Click here to change your password{/t}'>
    <input type='hidden' id='formSubmit'>
    </div>
{/if}
    <!-- check, if cookies are enabled -->
    <p class='warning'>
     <script language="JavaScript" type="text/javascript">
        <!--
            document.cookie = "gosatest=empty;path=/";
            if (document.cookie.indexOf( "gosatest=") > -1 )
                document.cookie = "gosatest=empty;path=/;expires=Thu, 01-Jan-1970 00:00:01 GMT";
            else
                document.write("{$cookies}");
        -->
     </script>
    </p>

</form>

{$msg_dialogs}

<table class='iesucks'><tr><td>{$errors}</td></tr></table>

<!-- Place cursor in username field -->
<script language="JavaScript" type="text/javascript">
  <!-- // First input field on page
  focus_field('error_accept','uid','directory', 'username', 'current_password');
  next_msg_dialog();
  -->
</script>

</body>
</html>
