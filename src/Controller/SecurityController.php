<?php

namespace App\Controller;

use App\Entity\User;
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

        $user->setUuid(Uuid::v7());

        $userRepository->save($user, true);

        $response->setStatusCode(Response::HTTP_CREATED)
            ->setData(['uuid' => $user->getUuid()]);

        return $response;
    }

    private function isJson($string): bool
    {
        json_decode($string);
        return json_last_error() === JSON_ERROR_NONE;
    }
}
