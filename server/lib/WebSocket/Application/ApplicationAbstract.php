<?php
/**
 * WebSocket Server Application
 * 
 * @author Nico Kaiser <nico@kaiser.me>
 */
abstract class WebSocket_Application_ApplicationAbstract
{
    protected static $_instances = array();
    
    /**
     * Singleton 
     */
    protected function __construct() { }

    final private function __clone() { }
    
    public static function getInstanceByClassName($calledClassName)
    {
        if (!isset(self::$_instances[$calledClassName])) {
            self::$_instances[$calledClassName] = new $calledClassName();
        }

        return self::$_instances[$calledClassName];
    }

    public function onConnect($connection) { }

    public function onDisconnect($connection) { }
    
    public function onTick() { }

    public function onData($data, $client) { }
}