<?php

namespace App\Service;

use App\Entity\User;
use App\Repository\SessionRepository;

class AuthService
{

    private SessionRepository $sessionRepository;

    public function __construct(SessionRepository $sessionRepository){
        $this->sessionRepository = $sessionRepository;
    }
    public function authByAccessToken($accessToken): User|string
    {
        $session = $this->sessionRepository->findOneByAccessToken($accessToken);

        if ($session) {

            if ($session->getAccessTokenExpiry() <= \DateTime::createFromFormat('Y-m-d H-i', date('Y-m-d H-i'))) {
                return 'Access token expired';
            }

            return $session->getUser();
        }

        return 'Missing or invalid access token';
    }
}