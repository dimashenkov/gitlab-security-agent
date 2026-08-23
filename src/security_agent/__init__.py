"""AI security review gate for GitLab CI/CD.

Written by Dimitar Shenkov <dimitar.shenkov@gmail.com>, MIT licensed.
https://github.com/dimashenkov/gitlab-security-agent
"""

__version__ = "0.1.0"

# Kept here rather than duplicated into every renderer: the report, the job log
# and `--version` all sign the same work, and three copies of a URL is three
# chances for one of them to go stale.
__author__ = "Dimitar Shenkov"
__email__ = "dimitar.shenkov@gmail.com"
__license__ = "MIT"

PROJECT_NAME = "gitlab-security-agent"
PROJECT_URL = "https://github.com/dimashenkov/gitlab-security-agent"
AUTHOR_URL = "https://github.com/dimashenkov"
