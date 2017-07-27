<?php
/**
 * Pimcore
 *
 * This source file is available under two different licenses:
 * - GNU General Public License version 3 (GPLv3)
 * - Pimcore Enterprise License (PEL)
 * Full copyright and license information is available in
 * LICENSE.md which is distributed with this source code.
 *
 * @copyright  Copyright (c) Pimcore GmbH (http://www.pimcore.org)
 * @license    http://www.pimcore.org/license     GPLv3 and PEL
 */

namespace FrontendPermissionToolkitBundle\CoreExtensions\Navigation;


use FrontendPermissionToolkitBundle\Service;
use Pimcore\Http\RequestHelper;
use Pimcore\Model\Document;
use Pimcore\Model\Object\Concrete;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

class Builder extends \Pimcore\Navigation\Builder
{

    /**
     * @var Service
     */
    protected $service;

    /**
     * @var Concrete
     */
    protected $currentUser;



    public function __construct(RequestHelper $requestHelper, string $pageClass = null)
    {
        parent::__construct($requestHelper, $pageClass);
    }

    /**
     * @param Service $service
     */
    public function setService(Service $service)
    {
        $this->service = $service;
    }

    /**
     * @param TokenStorage $securityTokenStorage
     */
    public function setCurrentUser(TokenStorage $securityTokenStorage)
    {
        $this->currentUser = $securityTokenStorage->getToken()->getUser();
    }


    /**
     * @inheritdoc
     */
    protected function getChilds(Document $parentDocument)
    {
        $children = $parentDocument->getChildren();

        $allowedChildren = array();

        foreach($children as $child) {
            $permissionResource = $child->getProperty("permission_resource");

            if(empty($permissionResource) || $this->service->isAllowed($this->currentUser, $child->getProperty("permission_resource"))) {
                $allowedChildren[] = $child;
            }
        }

        return $allowedChildren;
    }

}
