<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Recipes;

/**
 * One input a recipe takes. Values are checked against $pattern and shell-quoted
 * into a NAME='value' binding, so they can't break out of it.
 */
final readonly class RecipeParam
{
    public function __construct(
        public string $name,
        public string $label,
        public string $placeholder,
        public bool $required,
        /** A regex the trimmed value must match (when not empty). */
        public string $pattern,
        public string $default = '',
    ) {}

    /**
     * @return array{name: string, label: string, placeholder: string, required: bool, default: string}
     */
    public function toArray(): array
    {
        return ['name' => $this->name, 'label' => $this->label, 'placeholder' => $this->placeholder, 'required' => $this->required, 'default' => $this->default];
    }
}
