{
    "title": "mini-1 comply",
    "compiled_by": "TheZoltan",
    "compiled_on": "2026-06-08T12:00:00Z",
    "items": [
        {
            "name": "1.1.1.1 Ensure mounting of cramfs filesystems is disabled",
            "labels": ["CIS"],
            "audit": [
                {
                    "cmd": "modprobe -n -v cramfs",
                    "audit_test_name": "cramfs_mod_available",
                    "response_conditions": [
                        {
                            "condition": "match",
                            "match_to": "install /bin/true",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                },
                {
                    "cmd": "lsmod | grep cramfs",
                    "audit_test_name": "cramfs_not_loaded",
                    "response_conditions": [
                        {
                            "condition": "match",
                            "match_to": "",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]                    
                }
            ]
        },
        {
            "name": "1.1.1.2 Ensure mounting of freevxfs filesystems is disabled",
            "labels": [],
            "audit": [
                {
                    "cmd": "modprobe -n -v freevxfs",
                    "audit_test_name": "freevxfs_mod_available",
                    "response_conditions": [
                        {
                            "condition": "match",
                            "match_to": "install /bin/true",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                },
                {
                    "cmd": "lsmod | grep freevxfs",
                    "audit_test_name": "freevxfs_not_loaded",
                    "response_conditions": [
                        {
                            "condition": "match",
                            "match_to": "",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                }
            ]
        },
        {
            "name": "1.1.1.3 Ensure mounting of jffs2 filesystems is disabled",
            "labels": ["CIS"],
            "audit": [
                {
                    "cmd": "modprobe -n -v jffs2",
                    "audit_test_name": "jffs2_mod_available",
                    "response_conditions": [
                        {
                            "condition": "match",
                            "match_to": "install /bin/true",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                },
                {
                    "cmd": "lsmod | grep jffs2",
                    "audit_test_name": "jffs2_not_loaded",
                    "response_conditions": [
                        {
                            "condition": "match",
                            "match_to": "",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                }
            ]
        },
        {
            "name": "1.1.1.4 Ensure mounting of hfs filesystems is disabled",
            "labels": ["CIS"],
            "audit": [
                {
                    "cmd": "modprobe -n -v hfs",
                    "response_conditions": [
                        {
                            "condition": "match",
                            "match_to": "install /bin/true",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                },
                {
                    "cmd": "lsmod | grep hfs",
                    "response_conditions": [
                        {
                            "condition": "match",
                            "match_to": "",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                }
            ]
        },
        {
            "name": "6.2.18 Ensure no duplicate user names exist",
            "labels": ["CIS"],
            "audit": [
                {
                    "cmd": "cat /etc/passwd| cut -f 1 -d : | grep -E -v \"^$\" | sort -n | uniq -c | grep -E -v -e \"^[[:space:]].*1\"",
                    "audit_test_name": "duplicate_users",
                    "response_conditions": [
                        {
                            "condition": "pass_if_no_lines",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                }
            ]
        },
        {
            "name": "6.2.19 Ensure no duplicate group names exist",
            "labels": ["CIS"],
            "audit": [
                {
                    "cmd": "cat /etc/group| cut -f 1 -d : | grep -E -v \"^$\" | sort -n | uniq -c | grep -E -v -e \"^[[:space:]].*1\"",
                    "audit_test_name": "duplicate_groups",
                    "response_conditions": [
                        {
                            "condition": "pass_if_no_lines",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                }
            ]
        },
        {
            "name": "6.2.20 Ensure shadow group is empty",
            "labels": ["CIS"],
            "audit": [
                {
                    "cmd": "grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group",
                    "response_conditions": [
                        {
                            "condition": "pass_if_no_lines",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                },
                {
                    "cmd": "awk -F: '($4 == \"<shadow-gid>\") { print }' /etc/passwd",
                    "response_conditions": [
                        {
                            "condition": "pass_if_no_lines",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                }
            ]
        },
        {
            "name": "Conditional test",
            "labels": [],
            "audit": [
                {
                    "cmd": "date | /bin/false",
                    "audit_test_name": "conditional_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                }
            ]
        },
        {
            "name": "Make sure ssh is not available",
            "labels": ["lockdown"],
            "pass_logic": "sshd_unavailable OR ( sshd_masked AND sshd_not_running )",
            "audit": [
                {
                    "cmd": "rpm -qa | grep -E '^openssh-[0-9].*$'",
                    "audit_test_name": "sshd_unavailable",
                    "response_conditions": [
                        {
                            "condition": "pass_if_no_lines",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                },
                {
                    "cmd": "systemctl is-enabled sshd",
                    "audit_test_name": "sshd_masked",
                    "response_conditions": [
                        {
                            "condition": "match",
                            "like_to": "masked",
                            "control_flag": "required",
                            "on": "stdout"
                        }
                    ]
                },
                {
                    "cmd": "systemctl is-enabled sshd",
                    "audit_test_name": "sshd_not_running",
                    "response_conditions": [
                        {
                            "condition": "match",
                            "like_to": "disabled",
                            "control_flag": "optional",
                            "on": "stdout"
                        },
                        {
                            "condition": "match",
                            "like_to": "Failed to get unit file state",
                            "control_flag": "optional",
                            "on": "stderr"
                        }
                    ]
                }
            ]
        },
        {
            "name": "Test A|(B&C) true true true",
            "labels": [],
            "pass_logic": "A_test OR ( B_test AND C_test )",
            "audit": [
                {
                    "cmd": "/bin/true",
                    "audit_test_name": "A_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                },
                {
                    "cmd": "/bin/true",
                    "audit_test_name": "B_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                },
                {
                    "cmd": "/bin/true",
                    "audit_test_name": "C_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                }
            ]
        },
        {
            "name": "Test A|(B&C) false true true",
            "labels": [],
            "pass_logic": "A_test OR ( B_test AND C_test )",
            "audit": [
                {
                    "cmd": "/bin/false",
                    "audit_test_name": "A_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                },
                {
                    "cmd": "/bin/true",
                    "audit_test_name": "B_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                },
                {
                    "cmd": "/bin/true",
                    "audit_test_name": "C_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                }
            ]
        },
        {
            "name": "Test A|(B&C) false false true",
            "labels": [],
            "pass_logic": "A_test OR ( B_test AND C_test )",
            "audit": [
                {
                    "cmd": "/bin/false",
                    "audit_test_name": "A_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                },
                {
                    "cmd": "/bin/false",
                    "audit_test_name": "B_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                },
                {
                    "cmd": "/bin/true",
                    "audit_test_name": "C_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                }
            ]
        },
        {
            "name": "Test A|(B&C) true false true",
            "labels": [],
            "pass_logic": "A_test OR ( B_test AND C_test )",
            "audit": [
                {
                    "cmd": "/bin/true",
                    "audit_test_name": "A_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                },
                {
                    "cmd": "/bin/false",
                    "audit_test_name": "B_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                },
                {
                    "cmd": "/bin/true",
                    "audit_test_name": "C_test",
                    "response_conditions": [
                        {
                            "condition": "exitcode",
                            "exit_result": 0,
                            "control_flag": "required",
                            "on": "return_code"
                        }
                    ]
                }
            ]
        }
    ]
}
