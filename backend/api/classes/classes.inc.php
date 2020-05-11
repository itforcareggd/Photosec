<?PHP // © THD@GGD 2018-2019

/**
  * Photosec app classes
  *
  * @author Thijs Houtenbos
  * @version 0.1.0
  * @package Photosec
  * @subpackage API
  */


  // Require all classes to be loaded
  $path = dirname(__FILE__);
  require_once($path . '/../../vendor/autoload.php');
  require_once($path . '/db.class.php');
  require_once($path . '/json.class.php');
  require_once($path . '/json_services.class.php');
  require_once($path . '/response.class.php');
  require_once($path . '/photosec.class.php');
  require_once($path . '/security.class.php');
  require_once($path . '/timer.class.php');
  require_once($path . '/variables.class.php');


?>