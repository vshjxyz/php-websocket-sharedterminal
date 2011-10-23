<?php
/**
 * Simple Echo WebSocket Application
 * 
 * @author Nico Kaiser <nico@kaiser.me>
 */
class WebSocket_Application_EchoApplication extends WebSocket_Application_ApplicationAbstract
{
    private $clients = array();
    
    protected static $_applicationName = 'WebSocket_Application_EchoApplication';
    
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

    public function onData($data, $client)
    {
        foreach ($this->clients as $sendto) {
            $sendto->send($data);
        }
    }
}