# AWS CLI Tools

A docker image for running AWS CLI commands.

It could be used in two ways:

1. You prefer to use your own version of AWS CLI but need to perform
  Shibboleth authentication to your account

1. You want to enjoy all available [AWS-related tools](#includes) by opening
  a bash session inside the container

## Usage: CLI for accounts with Shibboleth authentication

You can use this image to access Shibboleth-protected accounts.
To create a temporary session, just run `shib-auth` inside the container:

```bash
docker run --rm -it --volume "$HOME/.aws:/root/.aws" bostonuniversity/aws-tools shib-auth
```

Thanks to the `--volume "$HOME/.aws:/root/.aws"` piece, the security token generated
as the result of this command will be available at `~/.aws/credentials` so you'll be
able to use AWS CLI commands authenticated as the role you've chosen.

It is suggested to wrap the command above as an alias:

```bash
echo "alias awslogin='docker run --rm -it --volume \"$HOME/.aws:/root/.aws\" bostonuniversity/aws-tools shib-auth'" >> ~/.bashrc
# Source the file or re-login to your host
```

This session will only be available for a few hours but you can alway run that
command again to create a new one.

Note that this container will attempt to use Duo 2FA authentication but it's
been only tested for the `push` method (both manual and automated).

You can modify these environment variables to fine-tune for your own case:

Variable name        | Default value
---------------------|------------------------------
AWS_REGION           | `us-east-1`
AWS_OUTPUT_FORMAT    | `json`
AWS_LOGIN_URL        | `https://www.bu.edu/awslogin`

## Usage: Bash Session

### Bash

- Open aws-shell with default aws profile:

  ```bash
  docker run --rm -it \
    --volume "$HOME/.aws:/root/.aws" \
    --volume "$(pwd):/code" \
    bostonuniversity/aws-tools
  ```

- Open bash with a specific aws profile:

  ```bash
  docker run --rm -it \
    --volume "$HOME/.aws:/root/.aws" \
    --volume "$(pwd):/code" \
    -e AWS_PROFILE=<aws_profile> \
    bostonuniversity/aws-tools /bin/bash
  ```

- Persist the the shell history and other things across runs:

  ```bash
  docker run --rm -it \
    --volume aws-tools:/root \
    --volume "$HOME/.aws:/root/.aws" \
    --volume "$(pwd):/code" \
    bostonuniversity/aws-tools /bin/bash
  ```

### Windows CMD

In Windows, the syntax is a little bit different, for example:

```cmd
docker run --rm -it ^
--volume %cd%:/code ^
--volume C:\Some\Temporary\Directory:/root/.aws ^
--volume aws-tools:/root ^
bostonuniversity/aws-tools /bin/bash
```

### PowerShell

```powershell
docker run --rm -it --volume ${PWD}:/code --volume C:\Some\Temporary\Directory:/root/.aws --volume aws-tools:/root bostonuniversity/aws-tools /bin/bash
```

## Includes

### AWS

- `aws-cli`
- `aws-shell`
- `awsebcli`
- `ecs-cli`

### Other

- `bash`
- `less`
- `curl`
- `git`
- `jq`
- `groff`
- `py-pip`
- `python`
- `python3`
- `nodejs`
- `npm`
- `chromium`

## Development

To troubleshoot or add new features to this image, use `docker-compose`.

The first step is to build the image locally:

```bash
docker-compose build
```

Then, you can run the container with bash:

```bash
docker-compose run --rm aws bash
```
