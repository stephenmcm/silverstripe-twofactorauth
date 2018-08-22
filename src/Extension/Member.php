<?php

namespace _2fa\Extensions;

use OTPHP\TOTP;
use _2fa\BackupToken;
use _2fa\Authenticator;
use Endroid\QrCode\QrCode;
use ParagonIE\ConstantTime\Hex;
use SilverStripe\Forms\FieldList;
use ParagonIE\ConstantTime\Base32;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Core\Config\Config;
use SilverStripe\Security\Permission;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * @property \Member $owner
 * @property bool $Has2FA
 * @property string $TOTPToken
 *
 * @method BackupToken BackupTokens()
 */
class Member extends DataExtension
{
    private static $db = array(
        'Has2FA' => 'Boolean',
        'TOTPToken' => 'Varchar(160)',
    );

    private static $has_many = array(
        'BackupTokens' => '_2fa\BackupToken',
    );

    public function validateTOTP($token)
    {
        assert(is_string($token));

        $seed = $this->OTPSeed();
        if (!$seed) {
            return false;
        }
        $window = (int) Config::inst()->get(Authenticator::class, 'totp_window');
        $totp = TOTP::create($seed);

        $valid = $totp->verify($token);

        // Check backup tokens if unsuccessful
        if (!$valid) {
            $backup_tokens = $this->owner->BackupTokens()->filter('Value', $token);
            if ($backup_tokens->count()) {
                $candidate_backup_token = $backup_tokens->first();
                if ($token === $candidate_backup_token->Value) {
                    $valid = true;
                    $candidate_backup_token->delete();
                }
            }
        }

        return $valid;
    }

    private function getPrintableTOTPToken()
    {
        $seed = $this->OTPSeed();

        return $seed ? $seed : '';
    }

    private function OTPSeed()
    {
        if ($this->owner->TOTPToken) {
            $seed = $this->owner->TOTPToken;
            if (preg_match('/^[0-9a-f]+$/i', $seed)) {
                $seed = Hex::decode($this->owner->TOTPToken);
                $seed = trim(Base32::encodeUpper($seed), '=');
            }
            return $seed;
        }

        return;
    }

    /**
     * Allow other admins to turn off 2FA if it is set & admins_can_disable is
     * set in the config.
     * 2FA in general is managed in the user's own profile.
     *
     * @param \FieldList $fields
     */
    public function updateCMSFields(FieldList $fields)
    {
        // Generate default token (allows scanning the QR at the moment of
        // activation and (optionally) validate before activating 2FA)
        if (!$this->owner->TOTPToken
            && Config::inst()->get(Authenticator::class, 'validated_activation_mode')
        ) {
            $this->generateTOTPToken();
            $this->owner->write();
        }

        $fields->removeByName('TOTPToken');
        $fields->removeByName('BackupTokens');
        if (!(Config::inst()->get(Authenticator::class, 'admins_can_disable')
            && $this->owner->Has2FA && Permission::check('ADMIN'))
        ) {
            $fields->removeByName('Has2FA');
        }
    }

    public function updateFieldLabels(&$labels)
    {
        $labels['Has2FA'] = 'Enable Two Factor Authentication';
    }

    public function generateTOTPToken($bytes = 20)
    {
        $seed = trim(Base32::encodeUpper(random_bytes(20)), '=');
        $this->owner->TOTPToken = $seed;
    }

    /**
     * Delete a member's backup tokens when deleting the member.
     */
    public function onBeforeDelete()
    {
        foreach ($this->owner->BackupTokens() as $bt) {
            $bt->delete();
        }
        parent::onBeforeDelete();
    }

    private function getOTPUrl()
    {
        if (class_exists(SiteConfig::class)) {
            $config = SiteConfig::current_site_config();
            $issuer = $config->Title;
        } else {
            $issuer = explode(':', $_SERVER['HTTP_HOST']);
            $issuer = $issuer[0];
        }
        $label = sprintf('%s: %s', $issuer, $this->owner->Name);

        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s',
            rawurlencode($label),
            $this->getPrintableTOTPToken(),
            rawurlencode($issuer)
        );
    }

    public function generateQRCode()
    {
        $qrCode = new QrCode();
        $qrCode->setText($this->getOTPUrl());
        $qrCode->setSize(175);

        return $qrCode->getDataUri();
    }
    
    public function regenerateBackupTokens()
    {
        $member = $this->owner;
        $backup_token_list = $member->BackupTokens();
        foreach ($backup_token_list as $bt) {
            $bt->delete();
        }
        foreach (range(1, Config::inst()->get('_2fa\BackupToken', 'num_backup_tokens')) as $i) {
            $token = BackupToken::create();
            $backup_token_list->add($token);
        }
    }

    /**
     * Checks whether any of the member's Groups require to 2FA to log in
     *
     * @return boolean
     */
    public function is2FArequired()
    {
        foreach ($this->owner->Groups() as $group) {
            if ($group->Require2FA) {
                return true;
            }
        }
        return false;
    }
}
