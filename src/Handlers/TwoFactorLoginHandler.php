<?php

namespace _2fa\Security;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Security\Member;
use SilverStripe\Forms\Form;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\TextField;
use _2fa\Authenticators\TwoFactorMemberAuthenticator;


class TwoFactorLoginHandler extends \Firesphere\BootstrapMFA\Handlers\MFALoginHandler
{

    private static $url_handlers = [
        'verify' => 'secondFactor'
    ];
    private static $allowed_actions = [
        'LoginForm',
        'dologin',
        'secondFactor',
        'MFAForm'
    ];

    public function MFAForm()
    {
        // If no 2FA enabled return 2fa set up page, add extension call for this here?
        return new Form(
            $this,
            "MFAForm",
            new FieldList(
                new TextField('token', 'Security Token')
            ),
            new FieldList(
                new FormAction('completeSecondStep', 'Log in')
            )
        );
    }

    public function completeSecondStep($data, Form $form, HTTPRequest $request)
    {
        $member = $this->validate($data, $form, $request);
        if ($member) {
            $this->performLogin($member, $data, $request);
            
            return $this->redirectAfterSuccessfulLogin();
        }

        // Fail to login redirects back to form
        return $this->redirectBack();
    }
    
    /**
     * @param array $data
     * @param LoginForm $form
     * @param HTTPRequest $request
     * @return bool|Member
     */
    public function validate($data, $form, $request)
    {
        /** @var TwoFactorMemberAuthenticator $authenicator */
        $authenicator = new TwoFactorMemberAuthenticator();
        $memberID = $request->getSession()->get('MFALogin.MemberID');
        /** @var Member $member */
        $member   = $authenicator->validateToken(Member::get()->byID($memberID), $data['token'], $result);
        if ($result->isValid()) {

            return $member;
        }

        return false;
    }

}
