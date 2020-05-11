<?PHP // © THD @ GGD 2012-2018

/**
  * Timer
  *
  * @author Thijs Houtenbos
  * @version 0.3.0
  * @package Photosec
  * @subpackage Classes
  *
  **/

/**
  * Timer class
  *
  * This generic timer class can be used to measure exactly how
  * long different parts of the system take to be executed.
  * Multiple sub-timers can run concurrently trough this single class.
  * A sub-timer can be started and stopped multiple times,
  * the total amount between the start and stop calls will be added
  * and reported as the time spent inside the timer.
  *
  * The timers have a resolution up to 1 ms under PHP5 on Windows.
  *
  * Added schedule function (for use in a loop to time events)
  *
  * @package Photosec
  * @subpackage Classes
  */
  class timer {

    /** Timer precision (signuficant numbers when rounding), 4 should be equivalent to msec. resolution */
    const PRECISION = 4;

    /** Default timer name (when no sub-timer name is passed) */
    const DEFAULT_TIMER = 'default';

    /** @var array[string]float timer array or times keyed by sub-timer name */
    private static $timers;

    /** @var array[string]boolean timer array of current running start-times keyed by sub-timer name */
    private static $start;

    /** @var array[string]integer number of times a timer was started (to calculate average time per iteration) */
    private static $count;


  /**
    * Construct timer
    *
    * Allow direct timer construction, and reset when created (i.e. 'new timer()' means reset it all).
    */
    public function __construct() {
      // Init the timer array
      self::$timers = array();
      self::$start = array();
      self::$count = array();
    }


  /**
    * Start a timer
    *
    * Will start a sub-timer by storing the starting time.
    *
    * @param string $name (optional) name of the sub-timer
    * @return float the seconds already elapsed since start or 0
    */
    public static function start($name = self::DEFAULT_TIMER) {
      if (!isset(self::$timers[$name])) {
        // Create timer when needed
        self::$timers[$name] = 0;
        self::$count[$name] = 0;
      }
      if (!isset(self::$start[$name])) {
        // Start the timer when not started yet
        self::$start[$name] = microtime(true);
        self::$count[$name]++;
        return self::$timers[$name];
      } else {
        // Give message because something is wrong in the code
        debug("Timer '$name' was started more then once");
        return self::$timers[$name] + microtime(true) - self::$start[$name];
      }
    }


  /**
    * Stop a timer
    *
    * Will stop a timer by subtracting the start time from the current time
    * and adding it to the total time spent on this sub-timer.
    * This function will only work if the timer was started.
    *
    * @param string $name (optional) name of the sub-timer
    * @return float the total seconds elapsed rounded to precision
    */
    public static function stop($name = self::DEFAULT_TIMER) {
      // Create timer when needed
      if (!isset(self::$timers[$name])) {
        debug("Timer '$name' can't be stopped, it has never been started");
        return 0;
      }
      if (isset(self::$start[$name])) {
        // Stop the timer
        self::$timers[$name] += microtime(true) - self::$start[$name];
        unset(self::$start[$name]);
      } else {
        debug("Timer '$name' was already stopped");
      }
      // Return the total timer seconds
      return round(self::$timers[$name], self::PRECISION);;
    }


  /**
    * Check if a timer is running
    *
    * This function allows you to check if a timer is still running.
    *
    * @param string $name (optional) name of the sub-timer
    * @return boolean the timer is running
    */
    public static function running($name = self::DEFAULT_TIMER) {
      return isset(self::$timers[$name]);
    }


  /**
    * Get timer value
    *
    * Get the seconds elapsed for a single sub-timer, rounded to given precision in {@link timer::PRECISION}.
    * You can call this function after the timer has been started for the first time,
    * otherwise it will return a 0 value and report a debug notice.
    *
    * When the timer is still running you can get the running total time for the sub-timer without stopping it!
    *
    * @param string $name (optional) name of the sub-timer
    * @return float the total seconds elapsed rounded to precision
    */
    public static function get($name = self::DEFAULT_TIMER) {
      // Check if timer exists
      if (!isset(self::$timers[$name])) {
        // debug("Timer '$name' has never been started");
        return 0;
      }
      // Return current timer
      $timer = isset(self::$start[$name]) ? (self::$timers[$name] + microtime(true) - self::$start[$name]) : self::$timers[$name];
      return round($timer, self::PRECISION);
    }


  /**
    * Get timer value in msec
    *
    * Performs exactly as @see {timer::get()} but returns an integer in msec instead of a float in sec.
    *
    * @param string $name (optional) name of the sub-timer
    * @return integer the total msec elapsed rounded
    */
    public static function get_msec($name = self::DEFAULT_TIMER) {
      return round(self::get($name) * 1000);
    }


  /**
    * Get count value
    *
    * Get the number of times a single sub-timer started.
    * When the timer is still running you get the same count as after stopping!
    *
    * @param string $name (optional) name of the sub-timer
    * @return integer counter of the number of times a single sub-timer started
    */
    public static function count($name = self::DEFAULT_TIMER) {
      // Check if counter exists
      if (!isset(self::$count[$name])) {
        debug("Timer '$name' has never been started");
        return 0;
      }
      // Return current count
      return self::$count[$name];
    }


  /**
    * Output all timers to the debug
    *
    * This function will allow you to dump a list of all timers (running or stopped) for debugging purposes.
    */
    public static function debug() {
      foreach (self::$timers as $name => $timer) {
        if (isset(self::$start[$name])) {
          // Add running timers to the value
          $timer += microtime(true) - self::$start[$name];
        }
        debug("Timer '$name': " . round($timer, self::PRECISION) . " seconds");
      }
    }


  /**
    * Reset (and stops) the timer
    *
    * Activate with start
    *
    * @param string $name (optional) name of the sub-timer
    */
    public static function reset($name = self::DEFAULT_TIMER) {
      self::$timers[$name] = 0;
      self::$count[$name]  = 0;
      unset(self::$start[$name]);
    }


  /**
    * Schedule
    *
    * Schedule timer to fire at a certain times
    *
    * @param array[]string list of times to fire
    * @return schedule object
    */
    public static function schedule($times) {
      return new schedule($times);
    }


  }


?>