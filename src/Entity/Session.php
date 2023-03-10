<?php

namespace App\Entity;

use App\Repository\SessionRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: SessionRepository::class)]
class Session
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(targetEntity: User::class, inversedBy: 'sessions')]
    #[ORM\JoinColumn(nullable: false)]
    private ?user $user = null;

    #[ORM\Column(length: 255)]
    private ?string $accessToken = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE)]
    private ?\DateTimeInterface $accessTokenExpiry = null;

    #[ORM\Column(length: 255)]
    private ?string $refreshToken = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE)]
    private ?\DateTimeInterface $refreshTokenExpiry = null;

    #[ORM\Column]
    private ?bool $active = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUser(): ?user
    {
        return $this->user;
    }

    public function setUser(?user $user): self
    {
        $this->user = $user;

        return $this;
    }

    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }

    public function setAccessToken(string $accessToken): self
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    public function getAccessTokenExpiry(): ?\DateTimeInterface
    {
        return $this->accessTokenExpiry;
    }

    public function setAccessTokenExpiry(\DateTimeInterface $accessTokenExpiry): self
    {
        $this->accessTokenExpiry = $accessTokenExpiry;

        return $this;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(string $refreshToken): self
    {
        $this->refreshToken = $refreshToken;

        return $this;
    }

    public function getRefreshTokenExpiry(): ?\DateTimeInterface
    {
        return $this->refreshTokenExpiry;
    }

    public function setRefreshTokenExpiry(\DateTimeInterface $refreshTokenExpiry): self
    {
        $this->refreshTokenExpiry = $refreshTokenExpiry;

        return $this;
    }

    public function isActive(): ?bool
    {
        return $this->active;
    }

    public function setActive(bool $active): self
    {
        $this->active = $active;

        return $this;
    }

    public function toArray(): array
    {
        return [
            'access_token' => $this->getAccessToken(),
            'access_token_expiry' => $this->getAccessTokenExpiry(),
            'refresh_token' => $this->getRefreshToken(),
            'refresh_token_expiry' => $this->getRefreshTokenExpiry()
        ];
    }
}
