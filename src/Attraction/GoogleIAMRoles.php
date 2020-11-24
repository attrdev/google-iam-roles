<?php

namespace Attraction;

class GoogleIAMRoles
{

    private $googleClient, $applicationName, $projectId, $scopes, $guzzleClient, $cacheLayer = [];

    const CRM_ENDPOINT = 'https://cloudresourcemanager.googleapis.com/v1/projects';
    const SCOPES = ['https://www.googleapis.com/auth/cloud-platform'];

    public function __construct(string $applicationName, string $projectId)
    {

        $this->applicationName = $applicationName;
        $this->projectId = $projectId;

        $this->googleClient = new \Google_Client();
        $this->googleClient->setApplicationName($this->applicationName);
        $this->googleClient->setScopes(self::SCOPES);
        $this->googleClient->useApplicationDefaultCredentials();

        $this->guzzleClient = new \GuzzleHttp\Client();
    }

    private function emptyCache()
    {
        $this->cacheLayer = [];
    }

    private function cache($key, $value = false, $forceUpdate = false)
    {
        if ($forceUpdate) {
            unset($this->cacheLayer[$key]);
        }
        return $this->cacheLayer[$key] ?? $this->cacheLayer[$key] = ($value instanceof \Closure ? $value() : $value);
    }

    private function isCustomRole(string $role)
    {
        $base = sprintf('projects/%s/roles/', $this->projectId);
        if (strpos($role, $base) === false) {
            return false;
        }

        $segments = explode('/', $role);
        return $segments[count($segments) - 1];
    }

    private function hydrateCustomRole(string $role)
    {
        return sprintf('projects/%s/roles/%s', $this->projectId, $role);
    }

    private function getAccessToken()
    {
        $this->googleClient->fetchAccessTokenWithAssertion();
        $access_token = $this->googleClient->getAccessToken()['access_token'] ?? false;
        return $access_token;
    }

    public function removeRole(string $emailAddress, string $role)
    {
        return $this->removeRoles($emailAddress, [$role]);
    }

    public function removeRoles(string $emailAddress, array $roles)
    {

        $customRoles = array_map(function ($role) {
            return $this->hydrateCustomRole($role);
        }, $roles);

        $memberToRemove = sprintf('user:%s', $emailAddress);

        $res = $this->cache('getIamPolicy', function () {
            return $this->crmPost('getIamPolicy');
        });

        if (!$res['success'] || !isset($res['data']->bindings)) {
            return false;
        }

        $iamPolicy = $res['data'];

        foreach ($iamPolicy->bindings as $binding) {
            if (in_array($binding->role, $customRoles)) {
                if (in_array($memberToRemove, $binding->members)) {
                    $binding->members = array_diff($binding->members, [$memberToRemove]);
                }
            }
        }

        return $this->updateIamPolicy($iamPolicy);
    }

    public function addRole(string $emailAddress, string $role)
    {
        return $this->addRoles($emailAddress, [$role]);
    }

    public function addRoles(string $emailAddress, array $roles)
    {

        $customRoles = array_map(function ($role) {
            return $this->hydrateCustomRole($role);
        }, $roles);

        $memberToAdd = sprintf('user:%s', $emailAddress);

        $res = $this->cache('getIamPolicy', function () {
            return $this->crmPost('getIamPolicy');
        });

        if (!$res['success'] || !isset($res['data']->bindings)) {
            return false;
        }

        $iamPolicy = $res['data'];
        $added = [];

        foreach ($iamPolicy->bindings as $binding) {
            if (in_array($binding->role, $customRoles)) {
                if (!in_array($memberToAdd, $binding->members)) {
                    $binding->members[] = $memberToAdd;
                    $added[] = $binding->role;
                }
            }
        }

        $remainingRoles = array_diff($customRoles, $added);

        foreach ($remainingRoles as $role) {
            $iamPolicy->bindings[] = (object) [
                'role' => $role,
                'members' => [$memberToAdd]
            ];
            $added[] = $role;
        }

        return $this->updateIamPolicy($iamPolicy);
    }

    private function updateIamPolicy(object $iamPolicy)
    {

        $res = $this->crmPost('setIamPolicy', [
            'policy' => $iamPolicy
        ]);

        if ($res['success']) {
            $this->emptyCache();
            return true;
        }

        return false;
    }

    public function hasRole(string $emailAddress, string $role)
    {
        return $this->hasRoles($emailAddress, [$role]);
    }

    public function hasRoles(string $emailAddress, array $roles = [], bool $hasAllRoles = false)
    {

        $emailRolesMap = $this->cache('emailRolesMap', function () {
            $projectRoles = $this->getProjectRoles();

            $emailRolesMap = [];

            foreach ($projectRoles as $projectRole) {

                foreach ($projectRole['members'] as $member) {

                    $emailRolesMap[$member] = $emailRolesMap[$member] ?? [];
                    $emailRolesMap[$member][] = $projectRole['role'];
                }
            }

            return $emailRolesMap;
        });

        if (!array_key_exists($emailAddress, $emailRolesMap)) {
            return false;
        }

        $success = 0;
        $total = 0;

        foreach ($roles as $role) {
            if (in_array($role, $emailRolesMap[$emailAddress])) {
                $success++;
            }
            $total++;
        }

        return ($hasAllRoles ? ($success == $total) : ($success > 0));
    }

    public function getProjectRoles()
    {
        return $this->cache('getProjectRoles', function () {
            return $this->_getProjectRoles();
        });
    }

    private function getIamPolicy()
    {

        $res = $this->cache('getIamPolicy', function () {
            return $this->crmPost('getIamPolicy');
        });

        if (!$res['success'] || !isset($res['data']->bindings)) {
            return false;
        }

        return $res['data'] ?? false;
    }

    private function _getProjectRoles()
    {

        $iamPolicy = $this->getIamPolicy();
        if (!$iamPolicy) {
            return false;
        }

        $bindings = $iamPolicy->bindings ?? [];

        $roles = [];

        foreach ($bindings as $binding) {

            $iamRole = $this->isCustomRole($binding->role ?? '');

            if (!$iamRole) {
                continue;
            }

            $role = [
                'role' => $iamRole,
                'members' => []
            ];

            $members = $binding->members ?? [];
            foreach ($members as $member) {
                $split = explode(':', $member);
                if(!in_array($split,['user','group'])) {
                    continue;
                }
                $emailAddress = $split[1] ?? null;
                if (is_null($emailAddress)) {
                    continue;
                }
                $role['members'][] = $emailAddress;
            }
            exit();

            $roles[] = $role;
        }

        return $roles;
    }

    private function crmPost(string $method, array $body = [])
    {

        $finalUrl = sprintf(self::CRM_ENDPOINT . '/%s:%s?alt=json', $this->projectId, $method);
        $accessToken = $this->getAccessToken();
        if (!$accessToken) {
            return false;
        }

        $parameters = [
            'headers' => [
                'Authorization' => 'Bearer ' . $accessToken
            ],
            'http_errors' => false
        ];

        if (count($body) > 0) {
            $parameters['json'] = $body;
        }

        $res = $this->guzzleClient->request('POST', $finalUrl, $parameters);

        $success = ($res->getStatusCode() == 200);

        return [
            'success' => $success,
            'data' => json_decode(($res->getBody()->getContents() ?? '{}'))
        ];
    }
}
