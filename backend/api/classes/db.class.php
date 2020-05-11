<?PHP // © THD @ GGD 2012-2018

/**
  * MSSQL Database Handling
  *
  * @author Thijs Houtenbos
  * @version 0.1.1
  * @package Photosec
  * @subpackage Classes
  *
  **/


/**
  * Database class
  *
  * This class handles all the calls made to the database and insures that data is properly escaped.
  *
  * @package Photosec
  * @subpackage Classes
  */
  class db {

    /** Database handle */
    private static $dbh = null;

    /** System is currently in a transactional query */
    protected static $transaction = false;

    /** Cache for some frequently read results */
    protected static $cache = array();

    /** Remember DB errors */
    protected static $errors = array();

    /** Queue a single query to run after transaction ends */
    protected static $query_after_transaction = null;

    /** The current arguments for the query */
    protected static $arguments;

    /** The current stack for the query */
    protected static $stack;

    /** Fatal on error */
    public static $fatal_on_error = true;

    /** Echo on error (for debugging command line operation) */
    public static $echo_on_error = false;

    /** Ignore errors */
    public static $ignore_errors = false;

    /** Count the number of queries */
    private static $queries_count = 0;

    /** Enable profiling queries */
    private static $profile_queries_enable = false;

    /** Profiled queries */
    private static $profile_queries = array();

    /** Query timeout in seconds (should be positive) */
    public static $query_timeout = 600;

    protected static $text_cache = array();


    /////////////////////////////////////////////////////////////////////////////////////////////////
    // CONSTANTS ////////////////////////////////////////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////////////

    /** Constant regex for finding argument variables in the SQL query (modeled after PDO with added brackets for optional array arguments) */
    const SQL_ARGUMENT_REGEX            = '/(:[a-z_][a-z0-9_]*)(\[\])?/i';

    /** Constant regex for finding argument array variables in the SQL query (improvement of PDO, but be strict where arrays may be passed). DO NOT USE, it needs exactly 1 pass for correct stack order! */
    const SQL_ARGUMENT_ARRAY_REGEX      = '/(IN) ?\((:[a-z0-9_]+)\)/i';

    /** Constant regex for finding comments in the query (can be stripped) */
    const SQL_COMMENT_MULTILINE_REGEX   = '!/\*.*?\*/!s';

    /** Constant regex for finding comments in the query (can be stripped) */
    const SQL_COMMENT_REGEX             = '/--.*\n/';

    /** Constant regex for finding empty lines in the query (can be stripped) */
    const SQL_EMPTY_LINE_REGEX          = '/\n\s*\n/';

    /** Constant regex for finding and removing the MS code in the error message (for example: [Microsoft][SQL Server Native Client 11.0][SQL Server]) */
    const SQL_ERROR_CODE_PREFIX_REGEX   = '/^(\[[a-zA-Z0-9 \.]*\]){3}/';

    /** Constant added to argument to indicate an array */
    const SQL_ARGUMENT_ARRAY_INDICATOR  = '[]';

    /** Constant to replace arguments with once they are pushed to the stack */
    const SQL_ARGUMENT_PLACEHOLDER      = '?';

    /** Constant to replace null argument */
    const SQL_ARGUMENT_NULL             = 'NULL';

    /** Constant AND query */
    const SQL_AND                       = ' AND ';

    /** Constant count query. NOTE: add brackets to prevent errors with reserved keywords like 'trigger'. */
    const SQL_COUNT_QUERY               = 'SELECT COUNT(*) FROM [%s] %s;';

    /** Constant select from table. NOTE: adfd brackets to prevent errors with reserved keywords like 'trigger'. */
    const SQL_SELECT_QUERY              = 'SELECT %s * FROM [%s] %s %s;';

    /** Constant query to get last ed ID */
    const SQL_LAST_INSERT_ID            = 'SELECT @@IDENTITY;';

    /** Constant query to get next sequence ID */
    const SQL_NEXT_SEQUENCE             = 'SELECT nextval(%s);';

    /** Constant insert query */
    const SQL_INSERT_QUERY              = 'INSERT INTO [%s] (%s) VALUES %s %s;';

    /** Constant update query */
    const SQL_UPDATE_QUERY              = 'UPDATE [%s] SET %s WHERE %s;';

    /** Constant delete query */
    const SQL_DELETE_QUERY              = 'DELETE FROM [%s] WHERE %s;';

    /** Set ANSI nulls */
    const SQL_ANSI_NULLS                = 'SET ANSI_NULLS ON'; // 'SET ANSI_NULLS OFF' is deprecated;

    /** Set ANSI warnings */
    const SQL_ANSI_WARNINGS             = 'SET ANSI_WARNINGS ON'; // 'SET ANSI_WARNINGS OFF' helps prevent some errors (mostly with NULL value used in aggregate), but causes different (very random) errors.

    /** DB datetime format */
    const DB_DATETIME_FORMAT            = 'Y-m-d H:i:s';

    /** Query timeout in seconds*/
    const SQL_QUERY_TIMEOUT             = 600;

    /** Constants to define returing query data */
    const RETURN_RAW                    = 0; // Return all data as a result resource
    const RETURN_LAST                   = 1; // Return only the last result as an array
    const RETURN_ALL                    = 2; // Return all the data as an array of arrays
    const RETURN_NONE                   = 3; // Return no data (save memory)

    /** Constants to define returing query data */
    const PROFILE_QUERY_DEBUG_TRESHOLD  = 1;

    const TITEL               = 'titel';
    const TEKST               = 'tekst';
    const LINK                = 'link';
    const URL                 = 'url';


    /////////////////////////////////////////////////////////////////////////////////////////////////
    // CONSTRUCT & CONNECT //////////////////////////////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////////////


  /** Prevent direct construction */
    private function __construct() { } // Do nothing


  /** Prevent clone of the instance */
    public function __clone() {
      die("Clone is not allowed for singletons!");
    }


  /**
    * Check for database connection
    *
    * @return boolean success
    */
    public static function connected() {
      return self::$dbh ? true : false;
    }


  /**
    * Make database connection
    *
    * @return db singleton
    */
    public static function connect() {
      // Create singleton when needed
      if (!isset(self::$dbh)) {
        // Setting to ignore errors
        self::$ignore_errors = !config::db_debug_errors;

        // Connect to database
        if (!(self::$dbh = sqlsrv_connect(
          config::db_host, array(
            'Database'                  => config::db_name,
            'UID'                       => config::db_user,
            'PWD'                       => config::db_password,
            'CharacterSet'              => config::db_charset,
            'Encrypt'                   => false,
            'MultipleActiveResultSets'  => true,
            'ReturnDatesAsStrings'      => false,
            // 'TraceFile'                 => 'C:\Users\Thijs\AppData\Local\Temp\SQLtrace.log',
            // 'TraceOn'                   => true,
          ))
        )) {
          // Fatal error when database can't connect
          // debug('Database errors', sqlsrv_errors());
          die('Unable to connect to database.'); // . config::db_name);
        }
      }

      // Disable some ANSI behavior
      db::query(self::SQL_ANSI_NULLS);
      db::query(self::SQL_ANSI_WARNINGS);

      // Configure some options
      sqlsrv_configure('WarningsReturnAsErrors', 0); // 0 = nope, 1 = yup
      sqlsrv_configure('LogSubsystems', 11); // SQLSRV_LOG_SYSTEM_OFF = 0 (or -1 = ALL)
      sqlsrv_configure('LogSeverity', 1); // SQLSRV_LOG_SEVERITY_ERROR = 1 (or -1 = ALL)

      // Set default query timeout
      self::$query_timeout = self::SQL_QUERY_TIMEOUT;

      // Return handle
      return self::$dbh;
    }



    /////////////////////////////////////////////////////////////////////////////////////////////////
    // GENERIC QUERY FUNCTIONS //////////////////////////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////////////


  /**
    * Perform a query and return result
    *
    * The full result is returned as an array per row, containing an array of all columns in the row.
    *
    * Layout example (array layout semanticly clarified):
    * <code>
    *   // Full result as array (by default)
    *   $result = array(
    *     'row_1' => array( 'column_1' => 'value_a', 'column_2' => 'value_b' ),
    *     'row_2' => array( 'column_1' => 'value_c', 'column_2' => 'value_d' )
    *   );
    * </code>
    *
    * @param string MSSQL query to be executed
    * @param array[string]mixed named parameters to add to array
    * @param integer (default 1) return an array or array of arrays instead of a raw resultset
    * @return array[]array[string]mixed|mixed|null resultset from the query (null on failure)
    */
    public static function query($query, $arguments = array(), $return = self::RETURN_LAST) {
      if (!self::connected()) { return false; }

      // Convert UTF-8 to ANSI (fucking Microsoft SQL driver)...
      // $query = mb_convert_encoding($query, 'Windows-1252', 'UTF-8');

      // Clean the query (multiple regexes in one pass)
      $query = preg_replace(array(
        self::SQL_COMMENT_REGEX,
        self::SQL_COMMENT_MULTILINE_REGEX,
        self::SQL_EMPTY_LINE_REGEX
      ), array('', '', ''), $query);

      // Preparse the query (for PDO style arguments)
      self::$stack = array();
      self::$arguments = $arguments;
      $query = preg_replace_callback(db::SQL_ARGUMENT_REGEX, 'db::query_parse_argument', $query);

      // DEBUG
      // debug('SQL query', $query);

      // Show hard dump when the text 'DUMP' is in the query. By for example adding the line: RAISERROR ('DUMP', 0, 0);
      if (strpos($query, 'DUMP') > 0) {
        echo "\n\nQUERY:\n";
        echo $query;
        echo "\n\nSTACK:\n";
        var_dump(self::$stack);
        echo "\n\ARGUMENTS:\n";
        var_dump($arguments);
        if (config::gui_enable_output_handler) { ob_end_flush(); }
        exit();
      }

      // Execute the query and return result (stack is passed as static)
      return self::raw_query($query, $return);
    }


  /**
    * Perform raw query
    *
    * @param string $query
    * @param integer $return return type
    * @return resource
    */
    public static function raw_query($query, $return = self::RETURN_NONE) {
      // Keep time and perform query
      if (self::$profile_queries_enable) {
        // Run query with profiling
        if (!isset(self::$profile_queries[$query])) {
          // Init timer when not set
          self::$profile_queries[$query] = array(
            'query' => $query,
            'count' => 0,
            'time' => 0,
            'fetchtime' => 0,
            'totaltime' => 0
          );
        }
        self::$profile_queries[$query]['time'] -= timer::start('db_queries'); // Subtract current timer
        $result = self::mssql_perform_query($query);
        self::$profile_queries[$query]['time'] += timer::stop('db_queries'); // Add end timer
        self::$profile_queries[$query]['totaltime'] += self::$profile_queries[$query]['time'];
        self::$profile_queries[$query]['count']++; // Keep count
        if (self::$profile_queries[$query]['count'] < 10) {
          self::$profile_queries[$query]['params'][] = self::$stack; // Save query parameters
        }

      } else {
        // Run query and keep time the normal way
        timer::start('db_queries');
        $result = self::mssql_perform_query($query);
        timer::stop('db_queries');
      }
      self::$queries_count++;

      // Check for result
      if (!$result) {
        // Ignore errors
        if (self::$ignore_errors) { return; }

        // When an error occured gather error data
        $errors = sqlsrv_errors();
        $error_text = '';
        foreach ($errors as $error) {
          $error_text .= trim(preg_replace(self::SQL_ERROR_CODE_PREFIX_REGEX, '', $error[2])) . "\n";
        }
        $error_text = trim($error_text);

        // Check for really fatal database errors (that require a restart of the daemon)
        if (strpos($error_text, "Physical connection is not usable") !== false) {
          die("Database connection lost (probably because of a database shutdown). $error_text");
        }

        // Handle error (dump either to command line or process as normal or fatal error)
        if (self::$echo_on_error) {
          echo "Database error: $error_text (" . var_export(self::$stack, true) . ")\n";

          // Return nothing when an error has occurred
          return;
        } else if (self::$fatal_on_error) {
          // DEBUG
          // error('Query', $query);
          // error('Query param stack', self::$stack);
          die("Fatal database error: $error_text ($query / " . var_export(self::$stack, true) . ")");
        } else {
          // Return nothing when an error has occurred
          return;
        }
      } else {
        // When result is returned show notices
        if (!self::$ignore_errors) {
          if ($notices = sqlsrv_errors(SQLSRV_ERR_ALL)) {
            foreach ($notices as $notice) {
              $error_text = trim(preg_replace(self::SQL_ERROR_CODE_PREFIX_REGEX, '', $notice[2]));
              if ($error_text != '' && $error_text != 'Warning: The join order has been enforced because a local join hint is used.') {
                notice('Database notificatie', trim($error_text));
              }
            }
          }
        }
      }

      // Return nothing when nothing is required
      if ($return == self::RETURN_NONE) {
        sqlsrv_free_stmt($result);
        return;
      }

      // Return raw result when requested
      if ($return == self::RETURN_RAW) {
        return $result;
      }

      // Build array of rows, repeat when needed
      $data = array();
      do {
        $rows = array();
        if (self::$profile_queries_enable) {
          self::$profile_queries[$query]['fetchtime'] -= timer::start('db_queries'); // Subtract current timer
        }
        while ($row = sqlsrv_fetch_array($result, SQLSRV_FETCH_ASSOC)) {
          $rows[] = $row;
        }
        if (self::$profile_queries_enable) {
          self::$profile_queries[$query]['fetchtime'] += timer::stop('db_queries'); // Add end timer
          self::$profile_queries[$query]['totaltime'] += self::$profile_queries[$query]['fetchtime'];
        }

        // Either replace or add data
        if ($return == self::RETURN_LAST) {
          // Replace entire result array
          $data = $rows; // Replace with last
        } else {
          // Add result to beginning of array (RETURN_ALL is assumed here)
          array_unshift($data, $rows); // Add result to array in reverse order (last result is zero index)
        }
      } while (sqlsrv_next_result($result)!==null);

      // Clear result and return
      sqlsrv_free_stmt($result);
      return $data;
    }


  /**
    * Perform MSSQL query
    *
    * @param string $query the query
    * @param array[]mixed argument stack
    * @return resource result
    */
    public static function mssql_perform_query($query, $stack = null) {
      // Get static stack
      $stack = $stack === null ? self::$stack : $stack;

      // Perform query and return resource directly
      return sqlsrv_query(self::$dbh, $query, $stack, array(
        'QueryTimeout'              => self::$query_timeout,
        'SendStreamParamsAtExec'    => true, // Was false for unknown reason since sqlsrv_send_stream_data() is not used!!!
        // 'Scrollable'              => SQLSRV_CURSOR_FORWARD, // SQLSRV_CURSOR_STATIC
      ));
    }


  /**
    * Parse query arguments
    *
    * Replaces a single argument name with '?' and pushes the argument to the stack.
    *
    * This function will place a single null value on the stack when the argument is not set.
    *
    * DEVELOPERS NOTE: the regex match result contains the following numbered keys:
    * - 0 = the whole matched string
    * - 1 = the argument name (including the ':')
    * - 2 = the (optional) array indicator ('[]')
    *
    * @param array[]string argument name (regex callback) with ':' before it and optionally '[]' after it.
    * @return string '? or '?, ?, ?, ..., ?' for array arguments
    */
    public static function query_parse_argument($match) {
      // The argument name contains a ':' strip it
      $argument = substr($match[1], 1);
      $result = '';

      // Check if this is a single argument or an array
      if (isset($match[2]) && $match[2] == self::SQL_ARGUMENT_ARRAY_INDICATOR) {

        // Handle array, first check if an array is passed
        if (isset(self::$arguments[$argument]) && is_array(self::$arguments[$argument]) && count(self::$arguments[$argument]) > 0) {
          foreach (self::$arguments[$argument] as $value) {
            // Push a single array value to the stack and add to result
            self::$stack[] = $value;
            $result .= (($result == '') ? '' : ', ') . self::SQL_ARGUMENT_PLACEHOLDER;
          }
        } else {
          // Replace with NULL value
          $result = self::SQL_ARGUMENT_NULL;
        }

      } else {

        // Handle single argument, check if value is set
        if (isset(self::$arguments[$argument]) && self::$arguments[$argument] !== '' && self::$arguments[$argument] !== null) {
          // FORMERLY NO DATE CONVERSION NEEDED FOR MS SQL!!!

          // Prepare datetime objects here
          if (self::$arguments[$argument] instanceof datetime) {
            self::$arguments[$argument] = self::$arguments[$argument]->format(self::DB_DATETIME_FORMAT);
          }

          // Push the argument to the stack and set result
          self::$stack[] = self::$arguments[$argument];
          $result = self::SQL_ARGUMENT_PLACEHOLDER;
        } else {
          // Replace with NULL value
          $result = self::SQL_ARGUMENT_NULL;
        }

      }

      // Return the question mark(s) for MSSQL function to replace
      return $result;
    }


  /**
    * Perform a simple query with a single value result
    *
    * Directly return the single value instead of the array of rows.
    *
    * @param string MSSQL query to be executed
    * @param array[string]mixed named parameters to add to array
    * @return mixed the result
    */
    public static function squery($query, $arguments = array()) {
      $result = self::query($query, $arguments, self::RETURN_LAST);
      if (isset($result[0])) {
        return array_pop($result[0]);
      }
      return null;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////
    // GET/INSERT/UPDATE FUNCTIONS //////////////////////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////////////


  /**
    * Insert a single record into a table
    *
    * This function can work with zero, one or more keys:
    * - 0 keys means a boolean success variable will be returned
    * - 1 keys means a single key value (auto incremented) will be returned
    * - N keys means an array witk key values will be returned
    *
    * @param string $table SQL table to insert record in
    * @param array[string]string $values columns as array(key => value pairs)
    * @param array[]string $keys array of key column names to be returned
    * @return boolean|array[string]mixed success boolean or an array of key values when keys are passed
    */
    public static function insert($table, $values, $keys = array()) {
      // Get results from multi-insert
      $result = db::inserts($table, array($values), $keys);

      // Return the first record (instead of multi-dimensional array)
     if (is_array($result) && count($result) > 0) { $result = $result[0]; }

      // Get the first key when only one key is passed
      if (count($keys) == 1 && is_array($result) && count($result) > 0) { $result = $result[$keys[0]]; }

      // Return the end result
      return $result;
    }


  /**
    * Insert an array of records into a table
    *
    * @param string $table SQL table to insert record in
    * @param array[string]string $values columns as array(key => value pairs)
    * @param array[]string $keys array of key column names to be returned
    * @return boolean|array[]array[string]mixed success boolean or an array of rows containg key values when keys are passed
    */
    public static function inserts($table, $records, $keys = array()) {
      $names = "";
      $values = "";
      $returning = "";
      self::$stack = array();

      // Loop trough items and add to argument array
      foreach ($records as $nr => $record) {
        // Get keys only from the first row
        if ($names == "") { $names = implode(", ", array_keys($records[$nr])); }

        // Add values to list of arguments and only add questionmarks to the query
        $questionmarks = "";
        foreach ($record as $key => $value) {
          // Add value to the stack but convert datetime object to string again
          // if ($value instanceof DateTime) { warning("Date contains", $value->format('Y-m-d H:i:s')); }
          self::$stack[] = $value;
          $questionmarks .= ($questionmarks == "" ? "" : ", ") . '?';
        }
        $values .= ($values == "" ? "" : ", ") . "($questionmarks)";
      }

      // Returning keys
      if (is_array($keys) && count($keys) > 0) {
        $returning = "RETURNING " . implode(", ", $keys);
      }

      // Build query
      $table = trim($table, '[]'); // Trim the square brackets (that will be added again)
      $query = sprintf(self::SQL_INSERT_QUERY, $table, $names, $values, $returning);

      // DEBUG
      // debug("Insert query", $query);

      // Execute query
      // Return the result, or the boolean evaluation of the result, if no keys were given
      $result = db::raw_query($query);
      return empty($keys) ? !($result===false) : $result;
    }


  /**
    * Update a record in a table
    *
    * @param string $table SQL table to insert record in
    * @param array[string]string $values columns as array(key => value pairs)
    * @param array[string]string $key table primary key(s), use array to pass one or more key => value pairs
    * @return boolean success
    */
    public static function update($table, $values, $keys) {
      $fields = '';
      $where = '';
      self::$stack = array();

      // Fields
      foreach ($values as $key => $value) {
        $fields .= ($fields == '' ? "" : ", ") . "$key = ?";
        self::$stack[] = $value;
      }

      // Keys
      foreach ($keys as $key => $value) {
        $where .= ($where == '' ? '' : " AND ") . "$key = ?";
        self::$stack[] = $value;
      }

      // Build query
      $query = sprintf(self::SQL_UPDATE_QUERY, $table, $fields, $where);

      // DEBUG
      // debug("Update query", $query);

      // Perform query and return
      $result = db::raw_query($query);
      return !($result === false);
    }


  /**
    * Save a record in a table (insert / update)
    *
    * This function is an automatic selection between insert and update
    * - When one or more keys are not set or no keys are passed the record is inserted
    * - When all keys are set the record is updated
    *
    * Please not that when inserting the full record is required, but when updating you can also pass
    * just one or more columns to update (as long as the valid keys are also passed).
    *
    * @param string $table SQL table to save record in
    * @param array[string]string $values columns as array(key => value pairs)
    * @param array[string]string $keys table primary key(s), use array to pass one or more key => value pairs
    * @return boolean|integer success (anything !== false) can be true or newly inserted ID
    */
    public static function save($table, $values, $keys) {
      // DEBUG
      // debug("DB save '$table' entry", $values);

      // No keys are passed > insert
      if (!is_array($keys) || count($keys) < 1) {
        return db::insert($table, $values);
      }
      // Check if all keys are set (NOTE: 0 value keys evaluate to false too, avoid them!)
      foreach ($keys as $key) {
        if (!$key) {
          // A key is missing > insert and return the DB key values
          return db::insert($table, $values, array_keys($keys)); // keys need to be values instead of array key!
        }
      }
      // All keys present > update
      return db::update($table, $values, $keys);
    }


  /**
    * Delete one or more records from a table
    *
    * This function deletes a single record or a whole array of records from a table by a key.
    *
    * @param string $table SQL table to save record in
    * @param array[string]string|array[string]array[]string $keys table primary key(s), use arrays to pass one or more key => value(s) pairs to match
    * @return boolean success
    */
    public static function delete($table, $keys) {
      // Abort when no keys are passed!
      if (!is_array($keys) || count($keys) < 1) { return false; }

      // Build where
      $where = '';
      foreach ($keys as $key => $value) {
        $where .= ($where == '' ? '' : ' AND ') . db::one_or_many_comparison($key, $value);
      }

      // Build Query
      $query = sprintf(self::SQL_DELETE_QUERY, $table, $where);

      $result = db::squery($query);
      return !($result===false);
    }


  /**
    * Count records in a table
    *
    * You can specify multiple keys to match, and per key multiple values to match.
    *
    * WARNING: COLUMNS ARE NOT ESCAPED, SO NEVER ALLOW USER INPUT TO BE A COLUMN NAME!!!
    *
    * <code>
    *  // Example to count some comments
    *  $nr_comments = db::count('comment_table', array(
    *    'comment_user' => 'user',
    *    'comment_year' => 2009
    *  ));
    * </code>
    *
    * @param string $table SQL table to get records from
    * @param array[string]string|array[string]array[]string $keys table primary key(s), use arrays to pass one or more key => value(s) pairs to match
    * @return array[]array[string]mixed|null resultset of rows from this table (null on failure)
    */
    public static function count($table, $keys = array()) {
      // Build where query with supplied keys
      $query_where = '';
      foreach ($keys as $key => $value) {
        $query_where .= $query_where == "" ? "WHERE " : " AND ";
        $query_where .= db::one_or_many_comparison($key, $value);
      }

      // Build final query
      $query = sprintf(self::SQL_COUNT_QUERY, $table, $query_where);

      // DEBUG
      // debug("DB count query from '$table':", $query);

      // Perform query and return
      return db::squery($query);
    }


  /**
    * Get 0-N records from a table
    *
    * You can specify multiple keys to match, and per key multiple values to match.
    *
    * WARNING: COLUMNS ARE NOT ESCAPED, SO NEVER ALLOW USER INPUT TO BE A COLUMN NAME!!!
    *
    * <code>
    *  // Example to get some comments
    *  $comments = db::get('comment_table', array(
    *    'comment_user' => 'user',
    *    'comment_year' => 2009
    *  ));
    *
    *  // Example to get a series of specific comments
    *  $comments = db::get('comment_table', array(
    *    'comment_id' => array(1, 2, 3, 4, 5)
    *  ));
    *
    *  // This function also works great together with db::key to be able to find items fast in the array
    *  $comments = db::key($comments, 'comment_id');
    * </code>
    *
    * DEVELOPER NOTE: The limit is set to 0 to allow all records to be fetched, use this with caution. In all cases where you are dealing with a lot of records it is wise to use a logical limit...
    *
    * @param string $table SQL table to get records from
    * @param array[string]string|array[string]array[]string $keys table primary key(s), use arrays to pass one or more key => value(s) pairs to match
    * @param array[string]boolean $order (optional) order the results by column name (array keys). The value true means ascending and false descending.
    * @param integer $limit (optional) limited number of results, or leave at 0 for all results. Highly recommended to use when possible.
    * @param integer $offset (optional) start results from this numer, offset without limit is generally useless so this will only work with a limit > 0   DEVELOPER NOTICE: DOES NOT WORK!!!!
    * @return array[]array[string]mixed|null resultset of rows from this table (null on failure)
    */
    public static function get($table, $keys = array(), $order = array(), $limit = 0, $offset = 0) {
      // Build where query with supplied keys
      $query_where = '';
      foreach ($keys as $key => $value) {
        $query_where .= $query_where == "" ? "WHERE " : " AND ";
        $query_where .= db::one_or_many_comparison($key, $value);
      }

      // Build order query with supplied columns
      $query_order = '';
      if (!is_array($order)) { $order = array($order => true); }
      foreach ($order as $column => $asc) {
        $query_order .= $query_order == "" ? "ORDER BY " : ", ";
        $query_order .= $asc ? "$column ASC" : "$column DESC";
      }

      // Build limit query
      $query_limit = '';
      if ($limit > 0) {
        round($limit); round($offset);
        $query_limit = "TOP $limit"; // OFFSET $offset
      }

      // Build final query
      $query = sprintf(self::SQL_SELECT_QUERY, $query_limit, $table, $query_where, $query_order);

      // DEBUG
      // debug("DB get query from \"$table\": ", $query);

      // Perform query and return
      return db::query($query);
    }


  /**
    * Get a single record from a table
    *
    * You can pass a single key value as the second argument to automatically generate the key in the form of: $table + '_id'.
    *
    * @param string $table SQL table to get records from
    * @param array[string]string $keys table primary key(s), use array to pass one or more key => value pairs to match
    * @param array[string]boolean $order (optional) order the results by column name (array keys). The value true means lowest and false highest returned.
    * @return array[string]mixed|null single row from this table as array (or null on failure)
    */
    public static function get_one($table, $keys, $order = array()) {
      if (!is_array($order)) { $order = array($order => true); }
      if (!is_array($keys)) { $keys = array(($table . '_id') => $keys); }
      $result = db::get($table, $keys, $order, 1);
      return isset($result[0]) ? $result[0] : null;
    }


  /**
    * Get all records from a table
    *
    * Assumes standard ID in the table and keys by this ID.
    * When no caching is wanted and no ID keys are needed you should use {@see db::get()} instead.
    *
    * The recommended order will most often be: array('label' => true);
    *
    * @param string $table SQL table to get records from
    * @param array[string]boolean $order (optional) order the results by column name (array keys). The value true means lowest and false highest returned.
    * @param boolean $order (optional) reset cache and get results again
    * @return array[integer]array[string]mixed|null resultset of rows from this table keyed by primary ID (null on failure)
    */
    public static function get_all($table, $order = array(), $reset = false) {
      if (!is_array($order)) { $order = array($order => true); }
      $key = 'table_' . $table . '_' . md5(serialize($order));
      if ($reset || !isset(self::$cache[$key])) {
        self::$cache[$key] = db::key(db::get($table, array(), $order), $table . '_id');
      }
      return self::$cache[$key];
    }


  /**
    * One or many keys in a comparison
    *
    * This function takes a key name and a value consisting of a single string or an array of strings.
    *
    * @param string $key the key (column name)
    * @param array[]string|string $value the value(s), the string value 'NULL' will be evaluated as an actual NULL value
    * @return string the query part
    */
    public static function one_or_many_comparison($key, $values) {
      $v = db::escape($values);
      if (is_array($values) && $values) {
        return "$key IN (". implode(',', $v) . ')';
      } elseif (is_array($values) && !$values) {
        return "0=1";
      } elseif ($v == self::SQL_ARGUMENT_NULL) {
        return "$key IS NULL";
      } else {
        return "$key = $v";
      }
    }


  /**
    * Get the last insert ID
    *
    * @return int the last inserted ID.
    */
    public static function last_insert_id() {
      $result = db::squery(self::SQL_LAST_INSERT_ID);
      return $result;
    }


  /**
    * Get the next value of the sequence
    *
    * Returns the next sequence number and advances the sequence.
    * Use this for inserts where you need to know the ID.
    *
    * @todo make this MSSQL compatible!
    *
    * @param string $sequence the sequence name
    * @return integer the sequence number
    */
    public static function nextval($sequence) {
      return db::squery(sprintf(self::SQL_NEXT_SEQUENCE, db::escape($sequence)));
    }


  /**
    * Key array by a column value (this column should be a unique array key, when multiple of the same key are present the order is undefined!)
    *
    * Requires the rows, the key to be used and optionally the column.
    * When no column is given an array with all the values is given otherwise just that column value is given.
    *
    * DEVELOPERS NOTE: the $rows array is sacrificed
    *
    * @param array[]array[string]mixed $rows resultset to be re-keyed
    * @param string $key name of the column to key this array by
    * @param string $column (optional) name of a column to isolate from the result (leave NULL for all fields)
    * @return array[string]array[string]mixed with resultset keyed by column
    */
    public static function key($rows, $key, $column = null, $overwrite = true) {
      timer::start('dbkey');
      $result = array();
      //var_dump($rows);exit();
     if (is_array($rows)) {
        // Loop and unset item in original array
        // DEVELOPERS NOTE: use array_shift instead of array_pop to keep the array order!
        while ($row = array_shift($rows)) {
          if ($overwrite) {
            // Add result re-keyed (multiple of same key overwritten)
            $result[$row[$key]] = ($column === null) ? $row : $row[$column];
          } else {
            // Add result re-keyed (multiple of same key not overwritten)
            $result[$row[$key]][] = ($column === null) ? $row : $row[$column];
          }
        }
      } else {
        // warning('DB key requires an array or rows', $rows);
      }
      timer::stop('dbkey');
      return $result;
    }


  /**
    * Filter array
    *
    * The value should not be null or (by default) an empty string.
    * When multiple values are set (for some other key) they are both returned, the next function should determine the further order.
    *
    * @param array[]array[string]mixed $rows resultset to be filtered
    * @param string $key name of the column to filter this array by
    * @param string $value (optional) the value to discard (default is empty string '')
    */
    public static function filter($rows, $key, $value = '') {
      $result = array();
      if (is_array($rows)) {
        // Loop and unset item in original array
        while ($row = array_shift($rows)) {
          if ($row[$key] !== null && $row[$key] != $value) {
            // Add result when not empty or NULL
            $result[] = $row;
          }
        }
      } else {
        // warning('DB filter requires an array or rows', $rows);
      }
      return $result;
    }


  /**
    * Subvalue
    *
    * Get an array of a subvalue from an array (for example the ID of the full rows).
    *
    * @param array[]array[string]mixed $rows resultset
    * @param string $key name of the column to return values of
    */
    public static function subvalue($rows, $key) {
      $result = array();
      if (is_array($rows)) {
        // Loop and unset item in original array
        while ($row = array_shift($rows)) {
          // Add result if it exists
          if (isset($row[$key])) {
            $result[] = $row[$key];
          } else {
            // warning('DB subvalue key not found', $key);
          }
        }
      } else {
        // warning('DB subvalue requires an array or rows', $rows);
      }
      return $result;
    }


  /**
    * Escape a value for MSSQL
    *
    * Returns either a plain numeric value or a hex encoded string.
    *
    * @param mixed value
    * @return string escaped value
    */
    public static function escape($value) {
      // Return null firsy
      if ($value === null) { return self::SQL_ARGUMENT_NULL; }

      // Return number immediately
      if ($value === 0) { return '0'; } // Hack for correct zero processing
      if (is_numeric($value)) { return $value; }

      // Escape array values
      if (is_array($value)) {
        foreach ($value as $key => $item) {
          $value[$key] = self::escape($item);
        }
        return $value;
      }

      // Binary encode the rest for good safety
      $unpacked = unpack('H*hex', $value);
      return '0x' . $unpacked['hex'];
    }


  /**
    * Check if a given ID is a valid integer
    *
    * This function can be used to precheck if an integer ID is database-safe.
    * When an empty string is passed instead of a positive integer the database will
    * give an error because the integer won't be recognized and the function fails.
    * Also negative numbers or zero are invalid IDs (all IDs start at 1) so can be excluded.
    *
    * @param integer|mixed $id integer (or string containing an integer)
    * @return boolean the given value is valid
    */
    public static function is_id($id) {
      // Make sure we have an integer
      return (((integer) $id) > 0 && (is_int($id) || ctype_digit($id)));
    }


  /**
    * Get the requested ID
    *
    * Returns a valid ID in two cases:
    * - When the HTML class is inited with arguments received by an action call.
    * - When a value 'id' is passed in the POST
    *
    * @param boolean $mortal (optional) die when no valid ID is present
    * @return int valid ID (the first argument) or NULL
    */
    public static function id($mortal = true) {
      $result = ((isset(html::$args[0])) && db::is_id(html::$args[0])) ? html::$args[0] : variables::read('id', variables::ACTION_BOTH, null);
      if ($mortal && !$result) { die('Ongeldig ID'); }
      return $result;
    }


  /**
    * Set the requested ID
    *
    * Use to override the ID.
    *
    * @param integer $id
    */
    public static function set_id($id) {
      html::$args[0] = $id;
    }


  /**
    * Reset the ID
    *
    * Use this function before calling subpages that also rely on this function.
    * This is to prevent ID collisions when the subpage wrongfully assumes the ID is meant to find that object and the object exists by chance.
    */
    public static function reset_id() {
      html::$args = array();
    }


  /**
    * Get current object from DB
    *
    * This function will fail hard when no valid ID is present or the object does not exist.
    * Depends on {@see db::id()}.
    *
    * @param string $table the table name to get object from
    * @param boolean $mortal (optional) die when no ID is present
    * @return array[string]mixed the object fetched or null (only when mortal = false).
    */
    public static function current($table, $mortal = true) {
      $table_id   = db::id($mortal);
      $result     = $table_id ? db::get_one($table, array(($table . '_id') => $table_id)) : null;
      if ($mortal && !$result) {
        // debug("Result", $result);
        die("Object ID does not exist"); //, "$table/$table_id");
      }
      return $result;
    }


    ////////////////////////////////////////////////


  /**
    * Return count of queries that were run
    *
    * @return integer queries count
    */
    public static function queries_count() {
      return self::$queries_count;
    }


  /**
    * DateTime
    *
    * Create DateTime object
    *
    * @param string|DateTime date, optionally empty to use current date
    * @return DateTime object
    */
    public static function datetime($datetext = null) {
      $date = ($datetext === null) ? new DateTime() : $datetext;
      // Normal date format
      if (!($date instanceof DateTime)) { $date = DateTime::createFromFormat('d-m-Y', $datetext); }
      // Alternate date format
      if (!($date instanceof DateTime)) { $date = DateTime::createFromFormat('Y-m-d', $datetext); }
      // Check again and otherwise send fresh DateTime object
      return (($date instanceof DateTime) ? $date : new DateTime());
    }


  /**
    * Start profiling queries
    */
    public static function start_profiling_queries() {
      self::$profile_queries_enable = true;
    }


  /**
    * Stop profiling queries
    *
    * Stop profiling and return the queries. Reset the query profiling cache afterwards.
    *
    * @return array[string]float array keyed by query, sorted by duration
    */
    public static function stop_profiling_queries() {
      $result = self::$profile_queries;
      uasort($result, 'db::compare_profiling_queries');
      self::$profile_queries_enable = false;
      self::$profile_queries = array();
      return $result;
    }


  /**
    * Compare two times (used for profile sorting)
    */
    private static function compare_profiling_queries($profile1, $profile2) {
      $diff = $profile2['time'] - $profile1['time'];
      return $diff > 0 ? 1 : ($diff == 0 ? 0 : -1);
    }

  /**
    * Obtain appropriate text from a db [text] record
    */
    public static function get_text_from_db_row($tekst, $language = null, $subject = self::TEKST) {
      if ($language === null) $language = ml::current_language();
      if ($tekst) {
        $tekst_subject = $tekst[$subject . '_' . $language];
        if (!$tekst_subject && $language != ml::$default_lang && $tekst[$subject . '_' . ml::$default_lang]) {
          $tekst_subject = $tekst[$subject . '_' . ml::$default_lang];
          if (@$_REQUEST['debug_trans']) $tekst_subject = '!MISS! ' . $tekst_subject;
        }
        return $tekst_subject;
      } else {
        return '';
      }
    }

  /**
    * Obtain variable text from database ('text' table) by label, but it needs to have a tag_id or tag_groep_id to be shown
    *
    * @param string $label
    * @param string $language which language
    * @param string $subject which part of the text
    * @return string text
    */
    public static function get_text($label, $language = null, $subject = self::TEKST) {
      if (!array_key_exists($label, self::$text_cache)) {
        self::$text_cache[$label] = self::get_one('text', array('label' => $label));
      }
      $tekst = self::$text_cache[$label];

      $tekst_subject = static::get_text_from_db_row($tekst, $language, $subject);

      return $tekst && ($tekst['tag_id'] || $tekst['tag_groep_id'] || !$tekst['enabled_tag']) ? $tekst_subject : '';
    }


  /**
    * Convenience function to obtain variable text title from database ('text' table) by label, but it needs to have a tag_id or tag_groep_id to be shown
    *
    * @param string $label
    * @param string $language which language
    * @return string text
    */
    public static function get_title($label, $language = null) {
      return static::get_text($label, $language, self::TITEL);
    }


  /**
    * Filter a name of a database/table/column
    *
    * When a dynamic name is used in any query make sure only regular names can be used to prevent injection.
    *
    * @param string $name
    * @return string the filtered name
    */
    public static function filter_name($name) {
      return preg_replace("/[^A-Za-z0-9_]/", '', $name);
    }


    // END OF DB CLASS
  }





?>