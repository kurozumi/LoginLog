<?php

namespace Plugin\LoginLog;

use Eccube\Entity\Customer;
use Eccube\Entity\Member;
use Eccube\Request\Context;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\AuthenticationEvents;
use Symfony\Component\Security\Core\Event\AuthenticationFailureEvent;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;

class Event implements EventSubscriberInterface
{
    /**
     * @var RequestStack
     */
    private $requestStack;

    /**
     * @var Context
     */
    private $context;

    public function __construct(RequestStack $requestStack, Context $context)
    {
        $this->requestStack = $requestStack;
        $this->context = $context;
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return [
            SecurityEvents::INTERACTIVE_LOGIN => 'onInteractiveLogin',
            AuthenticationEvents::AUTHENTICATION_FAILURE => 'onAuthenticationFailure'
        ];
    }

    public function onInteractiveLogin(InteractiveLoginEvent $event)
    {
        $request = $event->getRequest();
        $user = $event->getAuthenticationToken()->getUser();

        if ($user instanceof Member) {
            logs('member-login')->info('成功', ['ログインID' => $user->getUsername(), 'IDアドレス' => $request->getClientIp()]);
        }

        if ($user instanceof Customer) {
            logs('customer-login')->info('成功', ['ログインID' => $user->getUsername(), 'IDアドレス' => $request->getClientIp()]);
        }
    }

    public function onAuthenticationFailure(AuthenticationFailureEvent $event)
    {
        $request = $this->requestStack->getCurrentRequest();
        $token = $event->getAuthenticationToken();

        if ($this->context->isAdmin()) {
            logs('member-login')->error('失敗', ['ログインID' => $token->getUsername(), 'IDアドレス' => $request->getClientIp()]);
        }

        if ($this->context->isFront()) {
            logs('customer-login')->error('失敗', ['ログインID' => $token->getUsername(), 'IDアドレス' => $request->getClientIp()]);
        }
    }
}
