# google-iam-roles
Manages your user's custom IAM roles. Useful for Google IAP protected applications. It only shows custom IAM roles, built-in roles are filtered out.

## Installation

It's recommended that you use [Composer](https://getcomposer.org/) to install google-iam-roles.

```bash
$ composer require attraction/google-iam-roles:^1.0
```

This will install google-iam-roles and all required dependencies. google-iam-roles requires PHP 7.4 or newer.

## Requirements
First, activate the Cloud Resource Manager API [here](https://console.developers.google.com/apis/api/cloudresourcemanager.googleapis.com/overview)

Second, make sure your service account has the `Project IAM Admin` role.

Third, this class uses `Application Default Credentials` to access Google Cloud - you can read about it [here](https://cloud.google.com/docs/authentication/production#passing_variable) if you're not familiar.

## Usage

```php
use Attraction\GoogleIAMRoles;

// Project ID is available in Google Cloud Project Settings - https://console.cloud.google.com/iam-admin/settings
$projectId = 'YOUR_PROJECT_ID';
$applicationName = 'A simple name to describe your application';

$iam = new GoogleIAMRoles($applicationName, $projectId);

/*
    Returns an object in this format:
    [
        {
            "role": "CustomRoleUser",
            "members": [
                "someone@john@doe.com"
            ]
        }
    ]
*/
$roles = $iam->getProjectRoles();

// Add role(s) to user
$iam->addRole('john@doe.com','CustomRoleAdmin');
$iam->addRoles('john@doe.com',['CustomRoleUser','CustomRoleAdmin']);

// Remove role(s) from user
$iam->removeRole('john@doe.com','CustomRoleAdmin');
$iam->removeRoles('john@doe.com',['CustomRoleUser','CustomRoleAdmin']);

// Test if user has a specific role
$iam->hasRole('john@doe.com','CustomRoleAdmin');

// Test if user has ANY of the roles
$iam->hasRoles('john@doe.com',['CustomRoleAdmin','CustomRoleUser']);

// Test if user has ALL the roles
$iam->hasRoles('john@doe.com',['CustomRoleAdmin','CustomRoleUser'], true);
```