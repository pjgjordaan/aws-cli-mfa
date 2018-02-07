# aws-cli-mfa
MFA helper script for AWS cli 

This script simplifies the process of getting STS tokens and adding the temporary credentials to credentials file. This is especially useful when you have mulitple AWS accounts and/or profiles that you need to manage temporary credentials for.

The temporary STS credentials are stored under a new profile in you AWS credentials file, called mfa-<profile-name>. Whenever a modification is made to the credentials file, the existing credentials file is first backed-up. The serial number of the MFA device you use for each profile is cached locally so that you only need to provide it the first time that you use this tool.


## Setup

```bash
$ git clone git@github.com:godfried/aws-cli-mfa.git
$ cd aws-cli-mfa
$ venv_dir=~/.venvs/aws-cli-mfa
$ python3.6 -m venv ${env_dir}
$ source ${env_dir}/bin/activate
$ pip install -r requirements.txt
$ python mfa_helper.py --help
usage: mfa_helper.py [-h] -c CODE -p PROFILE [-r REGION] [-d DURATION]
                     [-s SERIAL_NUMBER] [--cache-path CACHE_PATH]
                     [--credentials-path CREDENTIALS_PATH]

optional arguments:
  -h, --help            show this help message and exit
  -c CODE, --code CODE  Authentication code from mfa device.
  -p PROFILE, --profile PROFILE
                        AWS profile to get a session for.
  -r REGION, --region REGION
                        AWS region to use. (default: eu-west-1)
  -d DURATION, --duration DURATION
                        Duration in seconds to keep the STS token valid for.
                        (default: 43200)
  -s SERIAL_NUMBER, --serial-number SERIAL_NUMBER
                        Serial number for your MFA device. ARN in the case of
                        a virtual device. Falls back to a cached value in
                        ~/.aws/serial_numbers.
  --cache-path CACHE_PATH
                        Path to the serial number cache. (default:
                        ~/.aws/serial_numbers)
  --credentials-path CREDENTIALS_PATH
                        Path to the AWS credentials file. (default:
                       ~/.aws/credentials)

```

## Usage

Initial Usage
```bash
$ python mfa_helper.py --code=123456 --profile=aws-profile --serial-number=arn:aws:iam::123456789100:mfa/user
2018-02-06 16:08:12,775 - aws-cli-mfa - INFO - Cached serial number 'arn:aws:iam::123456789100:mfa/user' for 'aws-profile' to '~/.aws/serial_numbers'
2018-02-06 16:08:13,645 - aws-cli-mfa - INFO - Previous credentials backed up to '~/.aws/credentials.1517929693.637029'
2018-02-06 16:08:13,646 - aws-cli-mfa - INFO - MFA credentials stored in profile 'mfa-aws-profile'
```

Using cached serial number:
```bash
$ python mfa_helper.py --code=654321 --profile=aws-profile
2018-02-06 16:06:33,844 - aws-cli-mfa - INFO - Retrieved cached serial number 'arn:aws:iam::123456789100:mfa/user' for 'aws-profile'
2018-02-06 16:06:35,089 - aws-cli-mfa - INFO - Previous credentials backed up to '~/.aws/credentials.1517929595.087957'
2018-02-06 16:06:35,091 - aws-cli-mfa - INFO - MFA credentials stored in profile 'mfa-aws-profile'
```
