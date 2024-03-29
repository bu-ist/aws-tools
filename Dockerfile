FROM alpine:3.13

# Configure less
ENV PAGER="less -r"
ENV AWS_REGION="us-east-1"
ENV AWS_OUTPUT_FORMAT="json"
ENV AWS_LOGIN_URL="https://www.bu.edu/awslogin"

# Install required packages
RUN set -ex; \
    apk --no-cache add \
      bash \
      less \
      curl \
      zip \
      git \
      jq \
      groff \
      py-pip \
      python3 \
      py3-bcrypt py3-cryptography py3-pynacl \
      chromium \
      udev \
      ttf-freefont \
      nodejs \
      npm; \
    npm install -g npm;

# Install aws-shell (which also installs aws-cli) and some dependencies
RUN pip3 install --upgrade \
      pip \
      aws-shell \
      awscli \
      boto==2.49.0 \
      pyppeteer==0.2.5

# Install ecs-cli
RUN curl -o /usr/local/bin/ecs-cli https://s3.amazonaws.com/amazon-ecs-cli/ecs-cli-linux-amd64-latest && chmod u+x /usr/local/bin/ecs-cli

# Add aws cli command completion
RUN echo "complete -C '/usr/bin/aws_completer' aws" >> ~/.bashrc

RUN mkdir /code
WORKDIR /code

RUN mkdir /aws-auth
ADD aws-auth/ /aws-auth/
ADD bin/ /usr/local/bin/

ENTRYPOINT [ "entrypoint.sh" ]
CMD [ "aws-shell" ]
