<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Recipes;

enum RecipeGroup: string
{
    /** One-time setup that makes a fresh box ready and hardened. */
    case Prepare = 'prepare';

    /** Ongoing maintenance (patches, reboot). */
    case Update = 'update';
}
