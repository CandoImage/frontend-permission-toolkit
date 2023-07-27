<?php

namespace FrontendPermissionToolkitBundle\Interface;

interface CustomProviderInterface
{
    public function getPermissionProvider(): CustomPermissionGetterInterface;
}
