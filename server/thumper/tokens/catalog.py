"""The honeytoken recommendation engine: which credentials to fake and where
attackers (incl. the Shai-Hulud npm worm) are known to scan for them.

`default_path` is the top recommendation; `suggested_paths` are other realistic,
attacker-inspected locations. Operators are NOT limited to these - the UI lets
them type any path. These are opinionated recommendations, nothing more.

Refs: CISA advisory 2025/09/23, Unit 42, Microsoft "Shai-Hulud 2.0", Akamai.
"""

TOKEN_TYPES = [
    {
        "type": "aws",
        "display_name": "AWS access key",
        "default_path": "~/.aws/credentials",
        "suggested_paths": [
            "~/.aws/credentials",
            "~/.aws/config",
            "~/.env",
            "~/project/.env",
        ],
        "description": "Fake AWS access key + secret. Planted in the standard "
                       "credentials file the worm parses first.",
    },
    {
        "type": "github",
        "display_name": "GitHub PAT",
        "default_path": "~/.config/gh/hosts.yml",
        "suggested_paths": [
            "~/.config/gh/hosts.yml",
            "~/.netrc",
            "~/.git-credentials",
            "~/.npmrc",            # npm auth token - Shai-Hulud's primary target
            "~/.env",
        ],
        "description": "Fake fine-grained GitHub personal access token. Shai-Hulud "
                       "exfiltrates these to self-replicate via the API.",
    },
    {
        "type": "gcp",
        "display_name": "GCP service account",
        "default_path": "~/.config/gcloud/application_default_credentials.json",
        "suggested_paths": [
            "~/.config/gcloud/application_default_credentials.json",
            "~/.config/gcloud/legacy_credentials/default/adc.json",
            "~/gcp-key.json",
            "~/service-account.json",
        ],
        "description": "Fake GCP service-account JSON key.",
    },
    {
        "type": "azure",
        "display_name": "Azure token",
        "default_path": "~/.azure/accessTokens.json",
        "suggested_paths": [
            "~/.azure/accessTokens.json",
            "~/.azure/azureProfile.json",
            "~/.env",
        ],
        "description": "Fake Azure AD access token blob.",
    },
    {
        "type": "ssh",
        "display_name": "SSH private key",
        "default_path": "~/.ssh/id_rsa",
        "suggested_paths": [
            "~/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "/etc/ssh/ssh_host_rsa_key",
            "/etc/ssh/ssh_host_ed25519_key",
        ],
        "description": "Fake private key. Any read is almost certainly malicious. "
                       "Host-key paths (/etc/ssh/ssh_host_*_key) catch server-side snooping.",
    },
    {
        "type": "gitlab",
        "display_name": "GitLab PAT",
        "default_path": "~/.config/glab-cli/config.yml",
        "suggested_paths": [
            "~/.config/glab-cli/config.yml",
            "~/.python-gitlab.cfg",
            "~/.env",
            "~/.gitlab-ci.yml",
        ],
        "description": "Fake GitLab personal access token (glpat- prefix). "
                       "Attackers scan CI configs and dotfiles for these.",
    },
]

TOKEN_TYPE_NAMES = {token_type["type"] for token_type in TOKEN_TYPES}
