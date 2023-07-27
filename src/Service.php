<?php

/**
 * Pimcore
 *
 * This source file is available under two different licenses:
 * - GNU General Public License version 3 (GPLv3)
 * - Pimcore Commercial License (PCL)
 * Full copyright and license information is available in
 * LICENSE.md which is distributed with this source code.
 *
 * @copyright  Copyright (c) Pimcore GmbH (http://www.pimcore.org)
 * @license    http://www.pimcore.org/license     GPLv3 and PCL
 */

namespace FrontendPermissionToolkitBundle;

use Exception;
use FrontendPermissionToolkitBundle\CoreExtensions\ClassDefinitions\DynamicPermissionResource;
use FrontendPermissionToolkitBundle\CoreExtensions\ClassDefinitions\PermissionManyToManyRelation;
use FrontendPermissionToolkitBundle\CoreExtensions\ClassDefinitions\PermissionManyToOneRelation;
use FrontendPermissionToolkitBundle\CoreExtensions\ClassDefinitions\PermissionResource;
use FrontendPermissionToolkitBundle\Event\PermissionsEvent;
use FrontendPermissionToolkitBundle\Interface\CustomPermissionGetterInterface;
use FrontendPermissionToolkitBundle\Interface\CustomProviderInterface;
use Pimcore\Model\AbstractModel;
use Pimcore\Model\DataObject\ClassDefinition;
use Pimcore\Model\DataObject\ClassDefinition\Data;
use Pimcore\Model\DataObject\Concrete;
use Pimcore\Model\DataObject\Objectbrick;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class Service
{
    const DENY = 'deny';
    const ALLOW = 'allow';
    const INHERIT = 'inherit';

    /**
     * @var EventDispatcherInterface
     */
    protected EventDispatcherInterface $eventDispatcher;

    private array $permissionCache = [];

    /**
     * @param EventDispatcherInterface $eventDispatcher
     */
    public function __construct(EventDispatcherInterface $eventDispatcher)
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * returns array of all permission resources of given object
     * automatically merges all permission resources of objects related to the given object with 'Permission Objects' or 'Permission Href'
     *
     * merging:
     * - when permission is set to allow / deny directly in object, this is always used
     * - otherwise optimistic merging is used -> once one permission is allowed, it stays that way
     *
     *
     * @param Concrete|CustomProviderInterface $object
     * @param array $visitedIds
     * @param UserInterface|null $user
     * @return array
     * @throws Exception
     */
    public function getPermissions(Concrete|CustomProviderInterface $object, array $visitedIds = [], ?UserInterface $user = null): array
    {
        // check if custom permission provider is provided to get permissions with custom implementation
        if ($object instanceof CustomProviderInterface) {
            return $this->getCustomPermissions($object, $user);

        }
        if (isset($this->permissionCache[$object->getId()])) {
            return $this->permissionCache[$object->getId()];
        }

        if (isset($visitedIds[$object->getId()])) {
            return [];
        } else {
            $visitedIds[$object->getId()] = true;
        }

        $fieldDefinitions = $object->getClass()->getFieldDefinitions();
        $permissions = $permissionObjects = [];

        // get permission resources directly in given object
        foreach ($fieldDefinitions as $fieldDefinition) {
            [$fieldPermissions, $fieldPermissionObjects] = $this->getPermissionsByFieldDefinition($object, $fieldDefinition);
            $permissions = array_merge($permissions, $fieldPermissions);
            $permissionObjects = array_merge($permissionObjects, $fieldPermissionObjects);
        }

        // get permission resources from related objects and merge them with permissions of base object
        $mergedPermissions = $permissions;
        foreach ($permissionObjects as $permissionObject) {
            $objectPermissions = $this->getPermissions($permissionObject, $visitedIds);
            $mergedPermissions = $this->mergeNestedObjectPermissions($mergedPermissions, $permissions, $objectPermissions);
        }

        $permissionsEvent = new PermissionsEvent($mergedPermissions, $object, $this);
        $this->eventDispatcher->dispatch($permissionsEvent, PermissionsEvent::POST_GET);
        $mergedPermissions = $permissionsEvent->getPermissions();

        $this->permissionCache[$object->getId()] = $mergedPermissions;

        return $mergedPermissions;
    }

    protected function getCustomPermissions(CustomProviderInterface $provider, ?UserInterface $user = null): array
    {
        return $provider->getPermissionProvider()->getPermissions($provider, $user);
    }

    /**
     * Base permissions take precedence when explicitly set to allow or deny.
     * Optimistic merging is used for nested permissions. Once allowed a permission stays allowed.
     *
     * @param array $mergedPermissions Already merged permissions
     * @param array $basePermissions Permissions of the base object
     * @param array $nestedPermissions Permissions of the nested object
     *
     * @return array Updated merged permissions
     */
    public function mergeNestedObjectPermissions(
        array $mergedPermissions,
        array $basePermissions,
        array $nestedPermissions
    ): array {
        foreach ($nestedPermissions as $key => $value) {
            if (
                (($basePermissions[$key] ?? null) === self::INHERIT || !array_key_exists($key, $basePermissions))
                && ($mergedPermissions[$key] ?? null) !== self::ALLOW
            ) {
                $mergedPermissions[$key] = $value;
            }
        }

        return $mergedPermissions;
    }

    /**
     * checks if given object is allowed for given resource
     *
     * @param Concrete|CustomProviderInterface $object
     * @param string $resource
     * @param UserInterface|null $user
     * @return bool
     * @throws Exception
     */
    public function isAllowed(Concrete|CustomProviderInterface $object, string $resource, ?UserInterface $user = null): bool
    {
        $permissions = $this->getPermissions($object, [], $user);
        // check for custom provider to have a custom check for allowed
        if ($object instanceof CustomProviderInterface) {
            return $object->getPermissionProvider()->isAllowed($permissions, $object, $resource);
        }
        return ($permissions[$resource] ?? false) == self::ALLOW;
    }

    /**
     * @param AbstractModel $object
     * @param Data $fieldDefinition
     *
     * @return array
     * @throws Exception
     */
    protected function getPermissionsByFieldDefinition(
        AbstractModel $object,
        ClassDefinition\Data $fieldDefinition
    ): array {
        $permissions = $permissionObjects = [];
        switch (true) {
            case $fieldDefinition instanceof PermissionManyToManyRelation:
                $permissionObjects = $object->get($fieldDefinition->getName());
                break;

            case $fieldDefinition instanceof PermissionManyToOneRelation:
                $manyToOneRelation = $object->get($fieldDefinition->getName());
                if ($manyToOneRelation) {
                    $permissionObjects = [$manyToOneRelation];
                }
                break;

            case $fieldDefinition instanceof PermissionResource:
                $permissions = [$fieldDefinition->getName() => $object->get($fieldDefinition->getName())];
                break;

            case $fieldDefinition instanceof DynamicPermissionResource:
                $permissions = $object->get($fieldDefinition->getName());
                break;

            case $fieldDefinition instanceof ClassDefinition\Data\Objectbricks:
                /* @var $objectBrick Objectbrick */
                $objectBrick = $object->get($fieldDefinition->getName());
                foreach ($objectBrick->getBrickGetters() as $brickGetter) {
                    /* @var $brick Objectbrick\Data\AbstractData */
                    $brick = $objectBrick->$brickGetter();
                    if (!$brick) {
                        continue;
                    }

                    $brickFieldDefinitions = $brick->getDefinition()->getFieldDefinitions();
                    foreach ($brickFieldDefinitions as $brickFieldDefinition) {
                        [$brickPermissions, $brickPermissionObjects] = $this->getPermissionsByFieldDefinition(
                            $brick,
                            $brickFieldDefinition
                        );
                        $permissions = array_merge($permissions, $brickPermissions);
                        $permissionObjects = array_merge($permissionObjects, $brickPermissionObjects);
                    }
                }
                break;
        }

        return [$permissions, $permissionObjects];
    }
}
