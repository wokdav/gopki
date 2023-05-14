# gopki
Design certificate hierarchies witout pain.

## Motivation
Creating lots of Certificate Authorities with lots of Subscribers can be a lot of trouble in testing environments. There is usually extensive configuration necessary and the generation involves a multi-step-process including Key Generation, CSR generation and Certificate issuance. And while this may fit production environments, test environment needs to be flexible allowing for a wide range of manipulations.

This is what `gopki` is for.

## How it works
For each entity you supply a config file. `Gopki` then goes through these config files and generates the appropriate certificates/keys in one single step.

### Getting started
Creating a minimal config for a root certificate may looks like this:
```yaml
version: 1
subject: CN=My Root CA
validity:
    duration: 25y
extensions:
    - basicConstraints:
        critical: yes
        content:
            ca: true
    - keyUsage:
        critical: yes
        content:
            - keyCertSign
```

Assuming this file is located in `foo/root.yaml`, you can then generate your certificate with
```
gopki sign foo/
```
and have your certificate and private key generated under `foo/root.pem`.

More sophisticated examples can be found in the `examples` folder.

## Features

### Generic certificate profiles
When a lot of subscribers need similar certificates, you can define certificate profiles that pre-set your extensions and allow validation against the subject DN.

### Define arbitrary extensions
To really test your edge-cases you can define custom extensions like this:

```yaml
extensions:
    - custom:
        critical: yes
        oid: 1.2.2.4
        raw: "!binary:AQIDBA=="
```

## Stability
Once this project reaches v1.0.0 breaking changes shall occur very rarely, if ever and result in a major version increase. However, prior to v1.0.0 breaking changes will occur more frequently as the featureset and design is still fluent. In any case, breaking changes will be denoted in the changelog.

## Disclaimer
This software must not be used for certificates in production environments. It makes no effort to generate/store/wipe secrets in a secure way.
