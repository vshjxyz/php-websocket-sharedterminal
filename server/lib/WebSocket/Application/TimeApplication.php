<?php
/**
 * Simple Time sending WebSocket Application
 * 
 * @author Nico Kaiser <nico@kaiser.me>
 */
class WebSocket_Application_TimeApplication extends WebSocket_Application_ApplicationAbstract
{
    private $clients = array();
    
    private $lastTime = 0;
    
    protected static $_applicationName = 'WebSocket_Application_TimeApplication';

    public static function getInstance() {        
        return parent::getInstanceByClassName(self::$_applicationName);
    }
    
    public function onConnect($client)
    {
        $this->clients[] = $client;
    }

    public function onDisconnect($client)
    {
        $key = array_search($client, $this->clients);
        if ($key) {
            unset($this->clients[$key]);
        }
    }
    
    public function onTick()
    {
        if (time() > $this->lastTime + 3) {
            $this->lastTime = time();
            foreach ($this->clients as $sendto) {
                $sendto->send(time());
            }
        }
    }
}