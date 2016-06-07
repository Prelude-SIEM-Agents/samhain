#! /usr/local/bin/php
<?php
   header("Content-type: text/xml; charset=iso-8859-1");
   
   /* IF YOU ARE USING MOD_PHP, DELETE FIRST LINE (#! /usr/...)
    * ELSE: SET CORRECT PATH TO PHP
    */

   echo "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n";
   echo "<!DOCTYPE samhain SYSTEM \"samhain.dtd\">\n";
   echo "<?xml-stylesheet type=\"text/xsl\" href=\"samhain.xsl\" ?>\n";
   echo "\n";
   echo "<logs>\n";
   $machine = $HTTP_POST_VARS["machine"];
   print "<req_machine>$machine</req_machine>\n";
   $date = $HTTP_POST_VARS["date"];
   print "<req_date>$date</req_date>\n";

   /* INSERT PATH TO YOUR LOGFILE !!! 
    */
   readfile("/var/log/yule/yule.log");

   /* INSERT PATH TO YOUR PID FILE !!!
    * The final </trail> is only written when the
    * daemon exits, threfore we need to supply it here. 
    */
   if (TRUE == file_exists("/var/run/yule.pid")) {
	echo "</trail>\n";
   fi

   echo "</logs>\n";
?>
