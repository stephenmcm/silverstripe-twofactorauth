<?php

namespace _2fa\Security;

use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;

class TwoFactorMemberAuthenticator extends MemberAuthenticator
{
    /**
     * @inherit
     */
    public function getLoginHandler($link)
    {
        return TwoFactorLoginHandler::create($link, $this);
    }
}
