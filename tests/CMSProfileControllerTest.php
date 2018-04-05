<?php

namespace _2fa;

use SilverStripe\Security\Member;
use SilverStripe\CMS\Controllers\CMSMain;
use SilverStripe\Control\Controller;

class CMSProfileControllerTest extends \SilverStripe\Dev\FunctionalTest {

    protected static $fixture_file = '2FAMemberTest.yml';
    protected $orig = array();
    public $autoFollowRedirection = false;

    public function __construct() {
        parent::__construct();
    }

    public function setUp() {
        parent::setUp();

        // We're testing 2FA here so we don't need to enforce any password strength
        Member::set_password_validator(null);
    }

    public function tearDown() {

        parent::tearDown();
    }

    public function testGetEditForm()
    {
        $member = $this->objFromFixture(Member::class, 'admin');
        $this->assertNotNull($member);

        // Login is required prior to accessing a CMS form.
        $this->loginWithPermission('ADMIN');

        // Get the form associated CMSProfileController
        $controller = CMSProfileController::create();
        $controller->setRequest(Controller::curr()->getRequest());
        $form = $controller->getEditForm($member->ID);
        $this->assertNull($form->Fields()->fieldByName('Root.TwoFactorAuthentication.BackupTokens'));

        $this->assertInstanceOf(\SilverStripe\Forms\CheckboxField::class, $form->Fields()->dataFieldByName('Has2FA'));
    }

    public function test_activate2FA()
    {
        $member = $this->objFromFixture(Member::class, 'user1');
        $this->session()->set('loggedInAs', $member->ID);

        $response = $this->post('admin/myprofile/EditForm', array(
            'action_save' => 1,
            'ID' => $member->ID,
            'FirstName' => 'FirstName',
            'Surname' => 'Surname',
            'Email' => $member->Email,
            'Locale' => $member->Locale,
            'Password[_Password]' => '',
            'Password[_ConfirmPassword]' => '',
            'Has2FA' => 1
        ));

        $member = $this->objFromFixture(Member::class, 'user1');

        $this->assertTrue((bool)$member->Has2FA, 'Has2FA field was changed');
        
        // Get the form associated CMSProfileController
        $controller = CMSProfileController::create();
        $controller->setRequest(Controller::curr()->getRequest());
        $form       = $controller->getEditForm($member->ID);
        $this->assertNotNull($form->Fields()->fieldByName('Root.TwoFactorAuthentication.BackupTokens'));
    }

    public function test_regenerate_token()
    {
        $member = $this->objFromFixture(Member::class, 'user1');
        $this->logInAs($member);
        
        $response = $this->post('admin/myprofile/EditForm',
            array(
            'action_save'                => 1,
            'ID'                         => $member->ID,
            'FirstName'                  => 'FirstName',
            'Surname'                    => 'Surname',
            'Email'                      => $member->Email,
            'Locale'                     => $member->Locale,
            'Password[_Password]'        => '',
            'Password[_ConfirmPassword]' => '',
            'Has2FA'                     => 1
        ));

        // Get the form associated CMSProfileController
        $controller = CMSProfileController::create();
        $controller->setRequest(Controller::curr()->getRequest());
        $form       = $controller->getEditForm($member->ID);
        $this->assertNotNull($form->Fields()->fieldByName('Root.TwoFactorAuthentication.BackupTokens'));
        
        $controller->regenerate_token(null, null);
        
        $form = $controller->getEditForm($member->ID);
        $this->assertNull($form->Fields()->fieldByName('Root.TwoFactorAuthentication.BackupTokens'));
    }
}
