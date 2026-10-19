<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Recipes;

use Kongpda\ServerConnect\Shell\Shims;

/**
 * An app-authored server script, run by id only: callers choose a recipe
 * and fill in its declared params, never the shell. Bodies use $SUDO, $APT,
 * $DOCKER and sc_wait_dpkg from the shims, and $SSH_PORT (the port the
 * connection uses, so the firewall recipe never locks it out).
 */
final readonly class Recipe
{
    /**
     * @param  list<RecipeParam>  $params
     */
    public function __construct(
        public string $id,
        public string $label,
        public string $summary,
        public RecipeGroup $group,
        public SafetyLevel $safety,
        public ?int $prepareOrder,
        public array $params,
        private string $body,
    ) {}

    /**
     * The full script for `sh -s`: marker, shims, the port and param bindings, then the body.
     *
     * @param  array<string, mixed>  $values
     *
     * @throws InvalidRecipeParam
     */
    public function script(int $sshPort, array $values = []): string
    {
        $bindings = 'SSH_PORT='.Shims::quote((string) $sshPort)."\n";

        foreach ($this->params as $param) {
            $value = trim(is_scalar($values[$param->name] ?? null) ? (string) $values[$param->name] : '');
            $value = $value === '' ? $param->default : $value;

            if ($value === '' && $param->required) {
                throw new InvalidRecipeParam("{$param->label} is required.", $param->name);
            }

            if ($value !== '' && (strlen($value) > 500 || preg_match($param->pattern, $value) !== 1)) {
                throw new InvalidRecipeParam("Invalid value for {$param->label}: {$value}", $param->name);
            }

            $bindings .= $param->name.'='.Shims::quote($value)."\n";
        }

        return Shims::script("server-connect:recipe-{$this->id}", $bindings.$this->body, strict: false);
    }

    /**
     * @return array{id: string, label: string, summary: string, group: string, safety: string, prepare_order: int|null, params: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'label' => $this->label,
            'summary' => $this->summary,
            'group' => $this->group->value,
            'safety' => $this->safety->value,
            'prepare_order' => $this->prepareOrder,
            'params' => array_map(fn (RecipeParam $param): array => $param->toArray(), $this->params),
        ];
    }
}
