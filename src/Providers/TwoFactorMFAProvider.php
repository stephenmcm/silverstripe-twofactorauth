<?php

namespace _2fa\Providers;

use Rych\OTP\Seed;
use Rych\OTP\TOTP;
use Endroid\QrCode\QrCode;
use Firesphere\BootstrapMFA\Providers\MFAProvider;
use SilverStripe\Core\Config\Config;
use SilverStripe\SiteConfig\SiteConfig;
use SilverStripe\Control\Controller;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

class TwoFactorMFAProvider implements MFAProvider
{

    protected $member;

    /**
     * @param string $token
     * @param null|ValidationResult $result
     * @return Member|bool
     */
    public function verifyToken($token, &$result = null)
    {
        if (!$result) {
            $result = new ValidationResult();
        }
        $member = $this->getMember();
        if(!$member) {
            $result->addError('Invalid member');

            return false;
        }

        if (!$member->Has2FA) {
            return $member;
        }
        $seed = $this->OTPSeed();
        if (!$seed) {
            return $member;
        }
        $window = (int) Config::inst()->get(__CLASS__, 'totp_window');
        $totp   = new TOTP($seed, array('window' => $window));

        if ($totp->validate($token)) {
            return $member;
        }

        $result->addError('Invalid token');

        return false;
    }

    /**
     * @return Member|null
     */
    public function getMember()
    {
        return $this->member;
    }

    /**
     * @param Member $member
     */
    public function setMember($member)
    {
        $this->member = $member;
    }

    /**
     * @throws \SilverStripe\ORM\ValidationException
     */
    public function updateTokens()
    {
        // Clear any possible tokens in the session, just to be sure
        Controller::curr()->getRequest()->getSession()->clear('tokens');

        if ($member = $this->getMember()) {
            /** @var DataList|BackupCode[] $expiredCodes */
            $expiredCodes = BackupCode::get()->filter(['MemberID' => $member->ID]);
            $expiredCodes->removeAll();

            BackupCode::generateTokensForMember($member);
        }
        // Fail silently
    }

    public function getPrintableTOTPToken()
    {
        $seed = $this->OTPSeed();

        return $seed ? $seed->getValue(Seed::FORMAT_BASE32) : '';
    }

    private function OTPSeed()
    {
        if ($this->member && $this->member->TOTPToken) {
            return new Seed($this->member->TOTPToken);
        }

        return false;
    }

    public function generateTOTPToken($bytes = 20)
    {
        $seed                    = Seed::generate($bytes);
        return $seed->getValue(Seed::FORMAT_HEX);
    }

    public function getOTPUrl()
    {
        if (class_exists(SiteConfig::class)) {
            $config = SiteConfig::current_site_config();
            $issuer = $config->Title;
        } else {
            $issuer = explode(':', $_SERVER['HTTP_HOST']);
            $issuer = $issuer[0];
        }
        $label = sprintf('%s: %s', $issuer, $this->member->Name);

        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s', rawurlencode($label), $this->getPrintableTOTPToken(),
            rawurlencode($issuer)
        );
    }

    public function generateQRCode()
    {
        $qrCode = new QrCode();
        $qrCode->setText($this->getOTPUrl());
        $qrCode->setSize(175);
        $qrCode->setMargin(0);

        return $qrCode->writeDataUri();
    }

}
