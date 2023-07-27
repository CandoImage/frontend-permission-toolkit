<?php

namespace FrontendPermissionToolkitBundle\Interface;

use Symfony\Component\Security\Core\User\UserInterface;

interface CustomPermissionGetterInterface
{
    public function getPermissions(CustomProviderInterface $object, ?UserInterface $user = null): array;

    public function isAllowed(array $permissions, CustomProviderInterface $object, string $resource): bool;
}
