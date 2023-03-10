<?php

namespace App\Controller;

use App\Entity\Task;
use App\Repository\TaskRepository;
use App\Service\AuthService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class TaskController extends AbstractController
{
    #[Route('/task/new', name: 'api_task_new', methods: ['POST'])]
    public function new(Request $request, TaskRepository $taskRepository, AuthService $authService): JsonResponse
    {
        $response = new JsonResponse();

        $authResponse = $authService->authByAccessToken($request->headers->get('authorization'));

        if (is_string($authResponse)) {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent($authResponse);
            return $response;
        }

        $user = $authResponse;

        $content = $request->getContent();
        if (!$this->isJson($content)) {
            $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                ->setContent('Request body is not in json format');
            return $response;
        }
        $content = json_decode($content);

        if (isset($content->title)) {
            $task = new Task();
            $task->setTitle($content->title);
        } else {
            $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                ->setContent('Missing \'title\' property');
            return $response;
        }

        if (isset($content->description)) {
            $task->setDescription($content->description);
        }

        if (isset($content->deadline)) {
            if (strtotime($content->deadline)) {
                $task->setDeadline(\DateTime::createFromFormat('Y-m-d H:i', $content->deadline));
            } else {
                $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                    ->setContent('Wrong deadline format');
                return $response;
            }
        }

        $task->setUser($user);
        $task->setCompleted(false);

        $taskRepository->save($task, true);

        $response->setStatusCode(Response::HTTP_CREATED)
            ->setData($task->toArray());
        return $response;
    }

    #[Route('/task/list', name:'api_task_list', methods: ['GET'])]
    public function list(Request $request, TaskRepository $taskRepository, AuthService $authService): JsonResponse
    {
        $response = new JsonResponse();

        $authResponse = $authService->authByAccessToken($request->headers->get('authorization'));

        if (is_string($authResponse)) {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent($authResponse);
            return $response;
        }

        $user = $authResponse;

        $tasks = $taskRepository->findByUser($user);
        $data = [];
        foreach ($tasks as $task) {
            $data[] = $task->toArray();
        }

        $response->setData($data);
        return $response;
    }

    #[Route('/task/{id}', name: 'api_task_show', methods: ['GET'])]
    public function show(Request $request, TaskRepository $taskRepository, AuthService $authService): JsonResponse
    {
        $response = new JsonResponse();

        $authResponse = $authService->authByAccessToken($request->headers->get('authorization'));

        if (is_string($authResponse)) {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent($authResponse);
            return $response;
        }

        $user = $authResponse;

        $task = $taskRepository->createQueryBuilder('t')
            ->where('t.id = :id')
            ->andWhere('t.user = :user')
            ->setParameters([
                ':id' => $request->get('id'),
                ':user' => $user
            ])
            ->getQuery()
            ->getResult();

        if (!$task) {
            $response->setStatusCode(Response::HTTP_NOT_FOUND)
                ->setContent('Task not found');
        } else {
            $response->setStatusCode(Response::HTTP_OK)
                ->setData($task[0]->toArray());
        }

        return $response;
    }

    #[Route('/task/edit/{id}', name:'api_task_edit', methods: ['PATCH'])]
    public function edit(Request $request, TaskRepository $taskRepository, AuthService $authService): JsonResponse
    {
        $response = new JsonResponse();

        $authResponse = $authService->authByAccessToken($request->headers->get('authorization'));

        if (is_string($authResponse)) {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent($authResponse);
            return $response;
        }

        $user = $authResponse;

        $task = $taskRepository->createQueryBuilder('t')
            ->where('t.id = :id')
            ->andWhere('t.user = :user')
            ->setParameters([
                ':id' => $request->get('id'),
                ':user' => $user
            ])
            ->getQuery()
            ->getResult();

        if (!$task) {
            $response->setStatusCode(Response::HTTP_NOT_FOUND)
                ->setContent('Task not found');
            return $response;
        }

        $task = $task[0];

        $content = $request->getContent();
        if (!$this->isJson($content)) {
            $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                ->setContent('Request body is not in json format');
            return $response;
        }
        $content = json_decode($content);

        if (isset($content->title)) {
            $task->setTitle($content->title);
        }

        if (property_exists($content, 'description')) {
            $task->setDescription($content->description);
        }

        if (property_exists($content, 'deadline')) {
            if (\DateTime::createFromFormat('Y-m-d H:i', $content->deadline)) {
                $task->setDeadline(\DateTime::createFromFormat('Y-m-d H:i', $content->deadline));
            } elseif ($content->deadline === null) {
                $task->setDeadline(null);
            } else {
                $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                    ->setContent('Wrong deadline format');
                return $response;
            }
        }

        if (property_exists($content, 'completed')) {
            if (!is_bool($content->completed)) {
                $response->setStatusCode(Response::HTTP_NOT_ACCEPTABLE)
                    ->setContent('Completed type must be boolean');
                return $response;
            }
            $task->setCompleted($content->completed);
        }

        $taskRepository->save($task, true);

        $response->setData($task->toArray());

        return $response;
    }

    #[Route('/task/delete/{id}', name:'api_task_delete', methods: ['DELETE'])]
    public function delete(Request $request, TaskRepository $taskRepository, AuthService $authService): JsonResponse
    {
        $response = new JsonResponse();

        $authResponse = $authService->authByAccessToken($request->headers->get('authorization'));

        if (is_string($authResponse)) {
            $response->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setContent($authResponse);
            return $response;
        }

        $user = $authResponse;

        $task = $taskRepository->createQueryBuilder('t')
            ->where('t.id = :id')
            ->andWhere('t.user = :user')
            ->setParameters([
                ':id' => $request->get('id'),
                ':user' => $user
            ])
            ->getQuery()
            ->getResult();

        if (!$task) {
            $response->setStatusCode(Response::HTTP_NOT_FOUND)
                ->setContent('Task not found');
            return $response;
        }

        $task = $task[0];

        $taskRepository->remove($task, true);

        $response->setStatusCode(Response::HTTP_OK)
            ->setData(['deleted' => $task->toArray()]);

        return $response;
    }

    private function isJson($string): bool
    {
        json_decode($string);
        return json_last_error() === JSON_ERROR_NONE;
    }
}
