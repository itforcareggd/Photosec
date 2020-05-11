<?PHP // © THD@GGD 2017

/**
  * JSON (JavaScript Object Notation)
  *
  * @author Thijs Houtenbos
  * @version 0.1.0
  * @package Sarphati IC
  * @subpackage API
  */


/**
  * JSON (JavaScript Object Notation) Class
  *
  * Use this class to encode JSON to be used in client-side script.
  * JSON is used primarily for encoding data in a format easily understood by JavaScript on the client side (in fact JSON ís JavaScript technically).
  * See {@link http://en.wikipedia.org/wiki/JSON} for technical information about JSON.
  *
  * This function can use the internal PHP function json_encode() when available for a factor 100(!) speedup, but this PHP extension is not required.
  *
  * DEVELOPERS NOTICE: Maximum array size = 65535. Internet Explorer will give an error when the *amount* of items exceeds this number.
  *
  * @package Sarphati IC
  * @subpackage API
  */
  class json {

  /**
    * Encode array of data to JSON
    *
    * Data is returned as encoded valid JSON.
    * The PEAR class {@link Services_JSON()} is used to encode the data.
    * Because the main function also sends headers the 'private' function {@link Services_JSON::_encode()} is used instead.
    * The data can be restored on the client side with the following code:
    * <code>
    *   // Read JSON in JavaScript
    *   var data = eval('(' + JSON + ')');
    * </code>
    *
    * @param array|string $data The data to be encoded as JSON
    * @return string JSON data
    */
    public static function encode($data) {
      // Check for internal PHP function (PHP 5.2+)
      if (function_exists('json_encode')) {

        // Encode with internal function
        $data = json_encode($data);

      } else {

        // Encode JSON with class
        $json = new Services_JSON();
        $data = $json->_encode($data);

      }
      return $data;
    }


  /**
    * Decode array of JSON data
    *
    * @param string $data JSON encoded data
    * @return array the data
    */
    public static function decode($data) {
      // Check for internal PHP function
      if (function_exists('json_encode')) {

        // Encode with internal function
        $data = json_decode($data, true);

      } else {

        // Decode JSON with class
        $json = new Services_JSON();
        $data = $json->decode($data);

      }

      return $data;
    }


  }


?>