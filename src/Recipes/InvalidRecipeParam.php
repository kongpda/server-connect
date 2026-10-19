<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Recipes;

use InvalidArgumentException;

final class InvalidRecipeParam extends InvalidArgumentException
{
    public function __construct(string $message, public readonly string $param)
    {
        parent::__construct($message);
    }
}
