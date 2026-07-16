# patient-care-aggregator-api

![Build](https://github.com/NHSDigital/patient-care-aggregator-api/workflows/Build/badge.svg?branch=master)

This is a specification for the _patient-care-aggregator-api_ API.

- `specification/` This [Open API Specification](https://swagger.io/docs/specification/about/) describes the endpoints, methods and messages exchanged by the API. Use it to generate interactive documentation; the contract between the API and its consumers.
- `sandbox/` This NodeJS application implements a mock implementation of the service. Use it as a back-end service to the interactive documentation to illustrate interactions and concepts. It is not intended to provide an exhaustive/faithful environment suitable for full development and testing.
- `scripts/` Utilities helpful to developers of this specification.
- `proxies/` Live (connecting to another service) and sandbox (using the sandbox container) Apigee API Proxy definitions.

Consumers of the API will find developer documentation on the [NHS Digital Developer Hub](https://digital.nhs.uk/developer).

The specifications can be found here:

- Consumer: https://digital.nhs.uk/developer/api-catalogue/patient-care-aggregator-fhir
- Producer: https://digital.nhs.uk/developer/api-catalogue/patient-care-aggregator-get-appointments
- Record Service: https://digital.nhs.uk/developer/api-catalogue/patient-care-aggregator-record-service/patient-care-aggregator-record-service-api

## Contributing

Contributions to this project are welcome from anyone, providing that they conform to the [guidelines for contribution](https://github.com/NHSDigital/patient-care-aggregator-api/blob/master/CONTRIBUTING.md) and the [community code of conduct](https://github.com/NHSDigital/patient-care-aggregator-api/blob/master/CODE_OF_CONDUCT.md).

### Licensing

This code is dual licensed under the MIT license and the OGL (Open Government License). Any new work added to this repository must conform to the conditions of these licenses. In particular this means that this project may not depend on GPL-licensed or AGPL-licensed libraries, as these would violate the terms of those libraries' licenses.

The contents of this repository are protected by Crown Copyright (C).

## Development

### Requirements

- make
- nodejs + npm/yarn
- [poetry](https://github.com/python-poetry/poetry)
- Java 8+

### Install

```
$ make install
```

#### Updating hooks

You can install some pre-commit hooks to ensure you can't commit invalid spec changes by accident. These are also run
in CI, but it's useful to run them locally too.

```
$ make install-hooks
```

### Environment Variables

Various scripts and commands rely on environment variables being set. These are documented with the commands.

:bulb: Consider using [direnv](https://direnv.net/) to manage your environment variables during development and maintaining your own `.envrc` file - the values of these variables will be specific to you and/or sensitive.

### Make commands

There are `make` commands that alias some of this functionality:

- `lint` -- Lints the spec and code
- `publish` -- Outputs the specification as a **single file** into the `build/` directory

### Testing

Each API and team is unique. We encourage you to use a `test/` folder in the root of the project, and use whatever testing frameworks or apps your team feels comfortable with. It is important that the URL your test points to be configurable. We have included some stubs in the Makefile for running tests.

### VS Code Plugins

- [openapi-lint](https://marketplace.visualstudio.com/items?itemName=mermade.openapi-lint) resolves links and validates entire spec with the 'OpenAPI Resolve and Validate' command
- [OpenAPI (Swagger) Editor](https://marketplace.visualstudio.com/items?itemName=42Crunch.vscode-openapi) provides sidebar navigation

### Emacs Plugins

- [**openapi-yaml-mode**](https://github.com/esc-emacs/openapi-yaml-mode) provides syntax highlighting, completion, and path help

### Specification tooling

This repository currently uses OpenAPI Generator to validate and publish bundled specifications, and Redocly to render static HTML documentation.

- `npm run lint` -- Validates each specification file
- `npm run publish` -- Outputs each specification as a **single file** into the `build/` directory

:bulb: The `publish` command is useful when uploading to Apigee which requires the spec as a single file.

### API Spec Changes

When proposing API spec updates, treat the pull request as the working record for the change. Once the proposed spec is ready, open or update the PR so the HTML docs can be generated and reviewed from the same branch, then use that PR to gather/collate feedback from the relevant stakeholders and capture sign-off.

This helps show the evolution of the proposed spec over time and keeps the discussion, generated docs, review comments, and approvals together in one place. Please keep the PR up to date as the spec iterates so reviewers can compare each revision against the previous state.

### Caveats

#### Swagger UI

Swagger UI unfortunately doesn't correctly render `$ref`s in examples, so prefer bundled specs or the generated static docs when reviewing rendered output.

#### Apigee Portal

The Apigee portal will not automatically pull examples from schemas, you must specify them manually.

### Platform setup

As currently defined in your `proxies` folder, your proxies do pretty much nothing.
Telling Apigee how to connect to your backend requires a _Target Server_, which you should call named `patient-care-aggregator-api-target`.
Our _Target Servers_ defined in the [api-management-infrasture](https://github.com/NHSDigital/api-management-infrastructure) repository.

:bulb: For Sandbox-running environments (`test`) these need to be present for successful deployment but can be set to empty/dummy values.

### Publishing

The downstream ADO pipelines for publishing to production are no longer supported. The workflows in this repo will help you update, lint and package the specifications ready for publishing, but wont actually publish the changes.

The full process is defined here: https://nhsd-confluence.digital.nhs.uk/spaces/WAYF/pages/1073028098/KT+NHSE+API+Management+APIM+Procedures
