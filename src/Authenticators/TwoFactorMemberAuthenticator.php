<?php

namespace _2fa\Authenticators;

use \Firesphere\BootstrapMFA\Authenticators\BootstrapMFAAuthenticator;
use _2fa\Providers\TwoFactorMFAProvider;
use _2fa\Security\TwoFactorLoginHandler;
use SilverStripe\ORM\ValidationResult;

class TwoFactorMemberAuthenticator extends BootstrapMFAAuthenticator
{
    /**
     * @inherit
     */
    public function getLoginHandler($link)
    {
        return TwoFactorLoginHandler::create($link, $this);
    }
    
    /**
     * @param Member $member
     * @param string $token
     * @param ValidationResult|null $result
     * @return bool|Member
     */
    public function validateToken($member, $token, &$result = null)
    {
        if (!$result) {
            $result = new ValidationResult();
        }

        $provider = new TwoFactorMFAProvider();
        $provider->setMember($member);
        if ($provider->verifyToken($token, $result)) {
            return $member;
        }

        $result->addError('Invalid token');

        return false;
    }

}
