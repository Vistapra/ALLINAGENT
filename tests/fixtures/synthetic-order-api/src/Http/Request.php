<?php

declare(strict_types=1);

namespace AcmeBistro\OrderApi\Http;

final class Request
{
    /** @var array<string, string> */
    private array $normalizedHeaders = [];

    /** @var array<string, mixed> */
    private array $decodedBody = [];

    private bool $jsonValid = true;

    /**
     * @param array<string, string> $headers
     * @param array<string, mixed>|null $parsedBody
     */
    public function __construct(
        private readonly string $method,
        private readonly string $path,
        array $headers = [],
        private readonly string $rawBody = '',
        ?array $parsedBody = null,
    ) {
        foreach ($headers as $name => $value) {
            $this->normalizedHeaders[strtolower(trim($name))] = trim((string) $value);
        }

        if ($parsedBody !== null) {
            $this->decodedBody = $parsedBody;
        } elseif ($this->rawBody !== '') {
            $decoded = json_decode($this->rawBody, true);
            if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
                $this->jsonValid = false;
            } else {
                $this->decodedBody = $decoded;
            }
        }
    }

    /**
     * @param array<string, mixed> $payload
     * @param array<string, string> $headers
     */
    public static function jsonRequest(
        string $method,
        string $path,
        array $payload = [],
        array $headers = [],
    ): self {
        $encoded = $payload === [] ? '{}' : (string) json_encode($payload, JSON_UNESCAPED_SLASHES);
        $headers['Content-Type'] = $headers['Content-Type'] ?? 'application/json';
        return new self(strtoupper($method), $path, $headers, $encoded, $payload);
    }

    public static function fromGlobals(): self
    {
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $path = (string) (parse_url($uri, PHP_URL_PATH) ?: '/');
        $headers = [];

        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $headerName = str_replace('_', '-', substr($key, 5));
                $headers[$headerName] = (string) $value;
            } elseif (in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true)) {
                $headerName = str_replace('_', '-', $key);
                $headers[$headerName] = (string) $value;
            }
        }

        $rawBody = (string) file_get_contents('php://input');
        return new self($method, $path, $headers, $rawBody);
    }

    public function method(): string
    {
        return strtoupper($this->method);
    }

    public function path(): string
    {
        return $this->path;
    }

    public function header(string $name, ?string $default = null): ?string
    {
        $key = strtolower(trim($name));
        return $this->normalizedHeaders[$key] ?? $default;
    }

    public function rawBody(): string
    {
        return $this->rawBody;
    }

    public function hasValidJson(): bool
    {
        return $this->jsonValid;
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->decodedBody;
    }

    public function input(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->decodedBody) ? $this->decodedBody[$key] : $default;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->decodedBody);
    }
}
