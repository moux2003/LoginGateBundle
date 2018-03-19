<?php

namespace Anyx\LoginGateBundle\Security;

use Symfony\Component\Security\Http\Firewall\UsernamePasswordJsonAuthenticationListener as BaseListener;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Anyx\LoginGateBundle\Service\BruteForceChecker;
use Anyx\LoginGateBundle\Security\Events as SecurityEvents;
use Anyx\LoginGateBundle\Event\BruteForceAttemptEvent;
use Anyx\LoginGateBundle\Exception\BruteForceAttemptException;

class UsernamePasswordJsonAuthenticationListener extends BaseListener
{
    /**
     * @var \Anyx\LoginGateBundle\Service\BruteForceChecker
     */
    protected $bruteForceChecker;

    /**
     * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
     */
    protected $dispatcher;

    /**
     * @return \Anyx\LoginGateBundle\Service\BruteForceChecker
     */
    public function getBruteForceChecker()
    {
        return $this->bruteForceChecker;
    }

    /**
     * @param \Anyx\LoginGateBundle\Service\BruteForceChecker $bruteForceChecker
     */
    public function setBruteForceChecker(BruteForceChecker $bruteForceChecker)
    {
        $this->bruteForceChecker = $bruteForceChecker;
    }

    /**
     * @return \Symfony\Component\EventDispatcher\EventDispatcherInterface
     */
    public function getDispatcher()
    {
        return $this->dispatcher;
    }

    /**
     * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $dispatcher
     */
    public function setDispatcher(EventDispatcherInterface $dispatcher)
    {
        $this->dispatcher = $dispatcher;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        if (!$this->getBruteForceChecker()->canLogin($request)) {
            $event = new BruteForceAttemptEvent($request, $this->getBruteForceChecker());

            $this->getDispatcher()->dispatch(SecurityEvents::BRUTE_FORCE_ATTEMPT, $event);

            throw new BruteForceAttemptException('Brute force attempt');
        }

        return parent::handle($event);
    }
}
