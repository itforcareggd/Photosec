<?PHP // © THD @ GGD 2008-2018

/**
  * Variable Handling
  *
  * @author Thijs Houtenbos
  * @version 0.1.1
  * @package Photosec
  * @subpackage Classes
  *
  **/


/**
  * Variable class
  *
  * This class performs the actual GET/POST variable reading in a safe way.
  * The most important function of this class is data validation.
  *
  * @package Photosec
  * @subpackage Classes
  */
  class variables {

    // Constants
    const VALUE_DEFAULT               = null; // When the default value is set to null the value variables::$default_value is used. To actually be able to use null set this value to NULL!
    const ACTION_DEFAULT              = 0;  // Just use the default setting (default POST, but can be overridden at runtime)
    const ACTION_POST                 = 1;  // Also used in forms class (NOTE: this includes the session)
    const ACTION_GET                  = 2;  // Also used in forms class
    const ACTION_COOKIE               = 3;  // For cookies
    const ACTION_BOTH                 = 4;  // Both GET AND POST

    // Variable types (see: https://www.owasp.org/index.php/OWASP_Validation_Regex_Repository)
    const VAR_EMAIL                   = '/^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}$/'; // DEVELOPERS NOTE: longest TLD in existence is now 24 characters
    const VAR_PHONE                   = '/(^\(?\+[0-9]{2}|^\(?\+[0-9]{2}\(0\)|^\(?\(\+[0-9]{2}\)\(0\)|^\(?00[0-9]{2}|^\(?0\)?)([0-9]{9}$|[0-9\-\s\)]{9,15}$)/';
    const VAR_DATE                    = '/^(19|20)[0-9]{2}-(0[0-9]|1[0-2])-(0[0-9]|1[0-9]|2[0-9]|3[0-1])$/';
    const VAR_LABEL                   = '/^[a-z]{1,50}$/';
    const VAR_LANGUAGE                = '/^[a-z]{2}$/';
    const VAR_BOOLEAN                 = '/^[01]$/';
    const VAR_BOOLEAN_COMMA_SEPARATED = '/^[01](,[01])*$/';
    const VAR_INTEGER                 = '/^-?[0-9]{1,20}$/'; // Max integer is 19 digits + negative sign
    const VAR_ID                      = '/^[0-9]{1,10}$/'; // Max integer for database identity is 10 digits
    const VAR_ID_COMMA_SEPARATED      = '/^[0-9]{1,10}(,[0-9]{1,10})*$/'; // Max integer for database identity is 10 digits
    const VAR_TEXT                    = '/^[a-zA-Z0-9\?$@#()\'"!,+\-=_:.&*\s\n]+$/';
    const VAR_CODE                    = '/^[a-zA-Z0-9]{16,64}$/';
    const VAR_USER                    = '/^[a-zA-Z0-9_\.@]{1,50}$/';
    const VAR_JWS                     = '/^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+\/=]*$/';
    const VAR_FILE                    = '/^(data:)([a-z]+\/[a-z]+);base64,.*$/';

    // Maximum amount of bits in an integer (this should be 32 in theory, but you also have the sign bit)
    const MAXIMUM_INTEGER_BITS        = 30; // 30 is on the safe sideof the theoretical maximum of 31

    /** @var int default action to use */
    public static $default_action     = self::ACTION_POST;

    /** @var int default value to use */
    public static $default_value      = '';

    /** @var array[string]mixed override values */
    public static $override           = array();


  /**
    * Strip a variable of 'magic' quotes
    *
    * @param string $value data to be un-escaped
    * @return string the value without any 'magic' quotes
    */
    public static function strip($value) {
      return (get_magic_quotes_gpc() ? stripslashes($value) : $value);
    }


  /**
    * Encode value to UCS-2
    *
    * @param string $value UTF-8 encoded data to be converted
    * @return string the value in UTC-2 encoding
    */
    public static function ucs2_encode($value) {
      return iconv("UTF-8", "UCS-2", $value);
    }


  /**
    * Does the source contain no values
    *
    * @param integer $method the method to read the values with
    * @return boolean no values set so source is empty
    */
    public static function none($method = self::ACTION_DEFAULT) {
      if ($method == self::ACTION_DEFAULT) { $method = self::$default_action; }

      $source = self::source($method);
      return empty($source);
    }


  /**
    * Get the source for a read operation
    *
    * This function returns the proper array of values as source for the read operation based on the method used.
    *
    * @param integer $method the method to read the values with
    * @return array[string]mixed the source of the values
    */
    public static function source($method = self::ACTION_DEFAULT) {
      if ($method == self::ACTION_DEFAULT) { $method = self::$default_action; }

      // Make sure the sources exist
      if (!isset($_GET)) { $_GET = array(); }
      if (!isset($_POST)) { $_POST = array(); }
      if (!isset($_COOKIE)) { $_COOKIE = array(); }

      // Return the source array based on method
      if ($method == variables::ACTION_GET) { return array_merge($_GET, self::$override); }
      if ($method == variables::ACTION_POST) { return array_merge($_POST, self::$override); }
      if ($method == variables::ACTION_BOTH) { return array_merge($_GET, $_POST, self::$override); } // POST overwrites GET?
      if ($method == variables::ACTION_COOKIE) { return $_COOKIE; } // You cannot override a cookie

      // Failed because of wrong option
      return null;
    }


  /**
    * Read all variables that are set
    *
    * @param integer $method the method to read the values with
    * @param string $default the default value to return when the requested value is not set
    * @return array[string]mixed the processed values
    */
    public static function read_all($method = self::ACTION_DEFAULT, $default = self::VALUE_DEFAULT) {
      if ($method == self::ACTION_DEFAULT) { $method = self::$default_action; }
      if ($default == self::VALUE_DEFAULT) { $default = self::$default_value; }

      // Get values
      $target = self::source($method);

      // Loop all items and read
      $values = array();
      foreach ($target as $name => $value) {
        // NOTE additional encoding not needed here, only for side cases
        // $values[$name] = self::strip($charset == 'UTF-8' ? $value : self::ucs2_encode($value));
        $values[$name] = self::strip($value);
      }
      return $values;
    }


  /**
    * Read a single variable
    *
    * @param string $name the name of the variable to read
    * @param integer $method the method to read the values with
    * @param string $default the default value to return when the requested value is not set
    * @return string the value or default value if none was set
    */
    public static function read($name, $method = self::ACTION_DEFAULT, $default = self::VALUE_DEFAULT) {
      if ($method == self::ACTION_DEFAULT) { $method = self::$default_action; }
      if ($default == self::VALUE_DEFAULT) { $default = self::$default_value; }

      // Get values
      $target = self::source($method);

      // Return the requested value
      return isset($target[$name]) ? self::strip($target[$name]) : $default;
    }


  /**
    * Check if a single variable is set
    *
    * @param string $name the name of the variable to read
    * @param integer $method the method to read the values with
    * @return boolean the value is set
    */
    public static function set($name, $method = self::ACTION_DEFAULT) {
      if ($method == self::ACTION_DEFAULT) { $method = self::$default_action; }

      // Get values
      $target = self::source($method);

      // Return value status
      return isset($target[$name]);
    }


  /**
    * Override a single or multiple variable(s)
    *
    * Pass either one single name, value pair or an array or name value pairs
    *
    * @param string|array $keys the name of the variable(s) to override
    * @param integer $method the method to read the values with
    * @return boolean the value is set
    */
    public static function override($keys, $value = null) {
      if (!is_array($keys)) { $keys = array($keys => $value); }
      foreach ($keys as $name => $value) {
        self::$override[$name] = $value;
      }
    }


  /**
    * Set a cookie to a certain value for the duration of the session
    *
    * @param string $name the name of the cookie
    * @param string $value the value of the cookie
    * @param int @expire timestamp or 0 to disable
    * @return boolean success
    */
    public static function set_cookie($name, $value, $expire = 0) {
      // Get the system URL in parts
      $url    = explode('/', config::security_domain);
      $host   = $url[0];
      $path   = isset($url[1]) ? "/{$url[1]}" : '/';

      // Set the cookie (only for the specified subpath, host, over HTTPS and with HTTPonly enabled)
      return setcookie($name, $value, $expire, $path, $host, config::security_force_https ? true : (isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] != 'off'), true);
    }


  /**
    * Delete a cookie
    *
    * Empty and set the expire to the most distant past possible (0 is reserved)
    *
    * @param string $name the name of the cookie
    * @result boolean success
    */
    public static function delete_cookie($name) {
      self::set_cookie($name, 'DELETED', 1);
    }


  /**
    * Convert empty strings to NULL
    *
    * This function converts empty strings to null, usefull for input fields that return
    * empty strings instead of null. The returned value can be passed to the database
    * without further processing (if the function or table accepts NULL values!).
    *
    * @param string $value the string value
    * @param boolean $strict (optional) use strict comparison instead of 'loose' ==.
    * @return string|null the value or null
    */
    public static function nullify($value, $strict = false) {
      // Handle array
      if (is_array($strict)) { return empty($value) ? null : $value; }

      // Handle string or other
      return ($strict ? $value === "" : $value == "") ? null : $value;
    }


  /**
    * Convert a value to an array of values
    *
    * This function will expand comma seperated values like the values from checkboxes into an array.
    * When no value is set an empty array will be returned.
    *
    * DEVELOPER NOTICE: Use this function instead of explode for compatibility (always returns array).
    *
    * @param string $value the value (a comma separated string)
    * @return array[]string list of values
    */
    public static function value_to_array($value) {
      // [GJ 01-12-2010] Major change. Only empty strings and null return empty array,
      // The inputs 0 and '0' both return array('0');
      return ($value === "" || $value === null) ? array() : explode(',', $value);
    }


  /**
    * Convert an array of values to a single value
    *
    * This function will create a comma seperated value from an array.
    * When an empty array is passed an empty string will be returned.
    *
    * @param array[]string $array the list of values
    * @return string the comma separated value
    */
    public static function array_to_value($array) {
      return is_array($array) ? implode(',', $array) : "";
    }


  /**
    * Convert a bitfield (integer) to an array of values
    *
    * This function converts an integer containing bit values to an array of the corresponding bits.
    * When no value is set an empty array will be returned.
    *
    * DEVELOPER NOTICE: There is a physical maximum amount of bits that can be stored in a normal integer.
    * When you try to add values over the maximum bit number they will not be encoded!
    * Keep the number of elements in a single bitfield below this number!
    * The lowest bit encoded is number 0 (encoded as 1). When you start counting at item 1 the bit value will be 2.
    *
    * Test staus: OK
    *
    * @param integer $value the single bit value
    * @return array[]integer list of values
    */
    public static function bits_to_array($value) {
      $result = array();
      // Loop trough all possible bits and add to array when the bit is set in the integer
      for ($bit = 0; $bit < self::MAXIMUM_INTEGER_BITS; $bit++) {
        if ((int)$value & (1 << $bit)) {
          $result[$bit] = $bit;
        }
      }
      return $result;
    }


  /**
    * Convert an array of values to a bitfield (integer)
    *
    * This function converts an an array of integers containing bit values to a bitfield of the corresponding bits.
    * When an empty or no array is given an empty string will be returned.
    *
    * DEVELOPER NOTICE: There is a physical maximum amount of bits that can be stored in a normal integer.
    * When you try to add values over the maximum bit number they will not be encoded!
    * Keep the number of elements in a single bitfield below this number!
    * The lowest bit encoded is number 0 (encoded as 1). When you start counting at item 1 the bit value will be 2.
    *
    * Test staus: OK
    *
    * @param array[]integer list of values
    * @return integer $value the bitfield value
    */
    public static function array_to_bits($array) {
      // Check if an array was passed, otherwise return ""
      if (!is_array($array) || count($array) == 0) { return ""; }

      // Loop trough all possible bits and filter these out of the array (it might contain other impossible values)
      // Also the value will be nice and sorted after this...
      $result = 0;
      for ($bit = 0; $bit < self::MAXIMUM_INTEGER_BITS; $bit++) {
        if (in_array($bit, $array)) {
          $result += 1 << $bit;
        }
      }
      // Return single bitfield
      return $result;
    }


  /**
    * Convert a properly formatted date to a timestamp
    *
    * Accepted date formats are:
    * - 20-04-1984 (dutch)
    * - 20-4-1984 (dutch without leading zeroes)
    * - 1984-04-20 (international)
    * - 1984-4-20 (international without leading zeroes)
    *
    * @param string $date the date
    * @return integer the timestamp or false on failure
    */
    public static function date_to_timestamp($date) {
      $date = new Date($date);
      return $date->getTimestamp();
    }


  /**
    * Is a variable set?
    *
    * And is the variable non-empty?
    *
    * @param string|array[]string $name one name or optionally an array of names
    * @param string $method (optional)
    * @return boolean the variable is set
    */
    public static function issset($name, $method = self::ACTION_DEFAULT) {
      $names = (array) $name;
      foreach ($names as $name) {
        $value = self::read($name, $method, self::VALUE_DEFAULT);
        if ($value === self::VALUE_DEFAULT || $value === '') {
          return false;
        }
      }
      return true;
    }


  /**
    * Validate variable
    *
    * Check a variable against a regex
    *
    * @param string $variable value
    * @param string $regex to validate
    * @return boolean
    */
    public static function validate($variable, $regex) {
      $result = preg_match($regex, $variable) ? true : false;
      return $result;
    }


  /**
    * Read valid
    *
    * Read variable and validate. Only returns valid values!
    *
    * @param string $name the name of the variable to read
    * @param string $regex to validate
    * @param (optional) integer $method the method to read the values with
    * @param (optional) string $default the default value to return when the requested value is not set
    * @param (optional) give an error when variable does not match (default)
    * @return string the value or default value if none was set
    */
    public static function read_valid($name, $regex, $method = self::ACTION_DEFAULT, $default = self::VALUE_DEFAULT, $error = true, $optional = false) {
      // Check if value is set (and if not optional give error or return default)
      if (!self::issset($name, $method)) {
        if ($error && !$optional) { new response_missing_variable($name); }
        return self::VALUE_DEFAULT;
      }
      // Read variable and validate
      $variable = v::read($name, $method, $default);
      $result = v::validate($variable, $regex);
      if ($error && !$result) { new response_invalid_variable($name); }
      return $variable;
    }


  /**
    * Read valid optional
    *
    * Read optional variable and validate. Only returns valid values or empty string (or another default if defined)!
    *
    * @param string $name the name of the variable to read
    * @param string $regex to validate
    * @param (optional) integer $method the method to read the values with
    * @param (optional) string $default the default value to return when the requested value is not set
    * @param (optional) give an error when variable does not match (default)
    * @return string the value or default value if none was set
    */
    public static function read_valid_optional($name, $regex, $method = self::ACTION_DEFAULT, $default = self::VALUE_DEFAULT, $error = true) {
      return self::read_valid($name, $regex, $method, $default, $error, true);
    }


  }




/**
  * Variable class shorthand
  *
  * This class is only added to allow shorter code to be used.
  * <code>
  *   // Instead of this
  *   $id = variable::get('id');
  *
  *   // Use this slightly shorter version
  *   $id = v::get('id');
  * </code>
  *
  * The name 'v' is chosen instead of the more logical 'var' since the latter is a PHP keyword and cannot be used reliably.
  * Besides that "V" just looks cool. ;-)
  *
  * @package Photosec
  * @subpackage Classes
  */
  class v extends variables {

    // Constants
    const POST                        = 1;  // Also used in forms class (NOTE: this includes the session)
    const GET                         = 2;  // Also used in forms class
    const COOKIE                      = 3;  // For cookies
    const BOTH                        = 4;  // Both GET AND POST

  }




?>