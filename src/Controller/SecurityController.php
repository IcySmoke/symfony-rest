<?php

namespace App\Controller;

use App\Entity\Session;
use App\Entity\User;
use App\Repository\SessionRepository;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Uid\Uuid;

class SecurityController extends AbstractController
{
    #[Route('/register', name: 'api_security_register', methods: ['POST'])]
    public function index(Request $request, UserRepository $userRepository, UserPasswordHasherInterface $passwordHasher): JsonResponse
    {
        $response = new JsonResponse();
        $content = $request->getContent();

        if (!$this->isJson($content)) {
            $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                ->setContent('Request body is not in json format');
            return $response;
        }

        $content = json_decode($content);

        if (property_exists($content, 'email')) {
            // TODO email validation
            $email = $content->email;
        } else {
            $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                ->setContent('Missing email');
            return $response;
        }

        if (property_exists($content, 'password')) {
            // TODO password validation
            $pass = $content->password;
        } else {
            $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                ->setContent('Missing password');
            return $response;
        }

        $user = new User();

        $user->setEmail($email)
            ->setPassword($passwordHasher->hashPassword($user, $pass));

        do {
            $uuid = Uuid::v7();
        } while ($userRepository->findOneByUuid($uuid));

        $user->setUuid($uuid);

        $userRepository->save($user, true);

        $response->setStatusCode(Response::HTTP_CREATED)
            ->setData(['uuid' => $user->getUuid()]);
        return $response;
    }

    #[Route('/login', name: 'api_security_login', methods: ['POST'])]
    public function login(Request $request, UserRepository $userRepository, SessionRepository $sessionRepository, UserPasswordHasherInterface $passwordHasher): JsonResponse
    {
        $response = new JsonResponse();
        $content = $request->getContent();

        if (!$this->isJson($content)) {
            $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                ->setContent('Request body is not in json format');
            return $response;
        }

        $content = json_decode($content);

        if (property_exists($content, 'email')) {
            // TODO email validation
            $user = $userRepository->findOneByEmail($content->email);
        } elseif (property_exists($content, 'uuid')) {
            $user = $userRepository->findOneByUuid($content->uuid);
        } else {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent('Missing Uuid or Email to login');
            return $response;
        }

        if (property_exists($content, 'password')) {
            $password = $content->password;
        } else {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent('Missing Uuid or Email to login');
            return $response;
        }

        if (!$passwordHasher->isPasswordValid($user, $password)) {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
            ->setContent('invalid password');
        }

        if ($activeSession = $sessionRepository->getActiveByUser($user)) {
            $activeSession->setActive(false);
            $sessionRepository->save($activeSession, true);
        }

        $accessTokenExpiry = date('Y-m-d H:i', strtotime('+1 hours'));
        $refreshTokenExpiry = date('Y-m-d H:i', strtotime('+20 days'));

        // Generate a JWT access token
        $header = json_encode(['alg' => 'HS256', 'typ' => 'JWT']);
        $payload = json_encode([
            'user_id' => $user->getId(),
            'exp' => $accessTokenExpiry
        ]);
        $signature = hash_hmac('sha256', $header . "." . $payload, getenv('JWT_SECRET'));
        $accessToken = base64_encode($header) . "." . base64_encode($payload) . "." . $signature;

        // Generate a refresh token
        do {
            $refreshToken = bin2hex(random_bytes(32));
        } while ($sessionRepository->findOneByRefreshToken($refreshToken));

        $session = new Session();

        $session->setUser($user);
        $session->setAccessToken($accessToken);
        $session->setRefreshToken($refreshToken);
        $session->setAccessTokenExpiry(\DateTime::createFromFormat('Y-m-d H:i', $accessTokenExpiry));
        $session->setRefreshTokenExpiry(\DateTime::createFromFormat('Y-m-d H:i', $refreshTokenExpiry));
        $session->setActive(true);

        $sessionRepository->save($session, true);

        $response->setStatusCode(Response::HTTP_OK)
            ->setData([
                'message' => 'Success',
                'session' => $session->toArray()
            ]);
        return $response;
    }

    #[Route('/logout', name: 'api_security_logout', methods: ['POST'])]
    public function logout(Request $request, SessionRepository $sessionRepository): JsonResponse
    {
        $response = new JsonResponse();

        $accessToken = $request->headers->get('authorization');
        $session = $sessionRepository->findOneByAccessToken($accessToken);

        if (!$session) {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent('Missing or invalid access token');
            return $response;
        }

        if (!$session->isActive()) {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent('Session already inactive');
            return $response;
        }

        $session->setActive(false);
        $sessionRepository->save($session, true);

        $response->setStatusCode(Response::HTTP_OK)
            ->setContent('Logged out');
        return $response;
    }

    #[Route('/refresh', name: 'api_security_refresh', methods: ['PATCH'])]
    public function refresh(Request $request, SessionRepository $sessionRepository): JsonResponse
    {
        $response = new JsonResponse();

        $accessToken = $request->headers->get('authorization');
        $session = $sessionRepository->findOneByAccessToken($accessToken);

        if (!$session) {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent('Missing or invalid access token');
            return $response;
        }

        if (!$session->isActive()) {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent('Session expired');
            return $response;
        }

        $content = $request->getContent();

        if (!$this->isJson($content)) {
            $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                ->setContent('Request body is not in json format');
            return $response;
        }

        $content = json_decode($content);

        if (property_exists($content, 'refresh_token')) {
            if ($session->getRefreshToken() == $content->refresh_token) {
                $accessTokenExpiry = date('Y-m-d H:i', strtotime('+1 hours'));
                $refreshTokenExpiry = date('Y-m-d H:i', strtotime('+20 days'));

                // Generate a JWT access token
                $header = json_encode(['alg' => 'HS256', 'typ' => 'JWT']);
                $payload = json_encode([
                    'user_id' => $session->getUser()->getId(),
                    'exp' => $accessTokenExpiry
                ]);
                $signature = hash_hmac('sha256', $header . "." . $payload, getenv('JWT_SECRET'));
                $accessToken = base64_encode($header) . "." . base64_encode($payload) . "." . $signature;

                // Generate a refresh token
                do {
                    $refreshToken = bin2hex(random_bytes(32));
                } while ($sessionRepository->findOneByRefreshToken($refreshToken));

                $session->setAccessToken($accessToken);
                $session->setRefreshToken($refreshToken);
                $session->setAccessTokenExpiry(\DateTime::createFromFormat('Y-m-d H:i', $accessTokenExpiry));
                $session->setRefreshTokenExpiry(\DateTime::createFromFormat('Y-m-d H:i', $refreshTokenExpiry));

                $sessionRepository->save($session, true);

                $response->setStatusCode(Response::HTTP_OK)
                    ->setData([
                        'message' => 'Success',
                        'session' => $session->toArray()
                    ]);
                return $response;
            } else {
                $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                    ->setContent('Invalid refresh_token');
                return $response;
            }
        } else {
            $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                ->setContent('Missing refresh_token');
            return $response;
        }
    }

    private function isJson($string): bool
    {
        json_decode($string);
        return json_last_error() === JSON_ERROR_NONE;
    }
}
