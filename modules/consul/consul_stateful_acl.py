#!/usr/bin/env python2.7

# import some libraries
DOCUMENTATION='''
module: consul_stateful_acl
short_description: "Not your grandma's consul_acl module!"
description:
  - Provides CRUD for consul ACL tokens based on token name and policy associations.
requirements:
  - "python >= 2.7"
  - python-consul
  - requests
author: "Kevin Phillips (kevin.phillips@omadahealth.com), Chris Constantine (chris@omadahealth.com), Alex Schlessinger (alex.schlessinger@omadahealth.com)"
options:
    username:
        description:
          - A string value to associate with a token
        required: yes
        aliases: ['user','name']
    host_uri:
        description:
          - A string value used to specify the consul cluster
        required: no
        default: "https://consul.omadahealth.net"
        aliases: ['url','host']
    force_update:
        description:
          - Update token if remote policy does not match declared value (policy or default)
        required: no
        aliases: ['update']
    mgmt_token:
        description:
          - Authorization token
        required: yes
    policy:
        description:
          - A string (in HCL) to associate with a token
        required: no
        default: 'key "" {\npolicy = "read"\n}\nservice "" {\n  policy = "read"\n}\n'
        aliases: ['rules']
    require_policy_match:
        description:
          - Allow policy mismatch between stored policy and given policy.  Will use stored policy, will not change, and should NOOP (under normal circumstances)
        required: no
    state:
        description:
          - Whether to ensure or delete the declared ACL
        required: no
        choices: ['present', 'absent']
        default: 'present'
'''

EXAMPLES='''
  - name: Initial (fresh) task execution [should change]
    consul_stateful_acl:
      user: foo
      host: http://localhost:8500
      mgmt_token: "{{ example_consul_server_config.acl_master_token }}"

  - assert:
      that:
        - initial_consul_acl_task | changed

  - name: Repeat initial task execution [should not change]
    consul_stateful_acl:
      user: foo
      host: http://localhost:8500
      mgmt_token: "{{ example_consul_server_config.acl_master_token }}"
    register: repeat_initial_consul_acl_task
    when: not ansible_check_mode

  - assert:
      that:
        - not repeat_initial_consul_acl_task | changed
    when: not ansible_check_mode

  - name: Attempt to update token without passing force [should fail]
    consul_stateful_acl:
      user: foo
      host: http://localhost:8500
      mgmt_token: "{{ example_consul_server_config.acl_master_token }}"
      policy: ' '
    register: update_fail_consul_task
    ignore_errors: yes
    when: not ansible_check_mode

  - assert:
      that:
        - update_fail_consul_task | failed
    when: not ansible_check_mode

  - name: Attempt to update token with force [should change]
    consul_stateful_acl:
      user: foo
      host: http://localhost:8500
      mgmt_token: "{{ example_consul_server_config.acl_master_token }}"
      policy: 'service "foobar" { policy = "write" }'
      update: yes
    register: update_change_consul_task

  - assert:
      that:
        - update_change_consul_task | changed
        - update_change_consul_task.acl.policy == 'service "foobar" { policy = "write" }'

  - name: Attempt to update token without force but with require_policy_match=no
    consul_stateful_acl:
      user: foo
      host: http://localhost:8500
      mgmt_token: "{{ example_consul_server_config.acl_master_token }}"
      require_policy_match: no
    register: update_require_policy_match_no_change_consul_task
    when: not ansible_check_mode

  - assert:
      that:
        - not (update_require_policy_match_no_change_consul_task | changed)
        - update_require_policy_match_no_change_consul_task.acl.policy == 'service "foobar" { policy = "write" }'
    when: not ansible_check_mode

  - name: Delete initial token
    consul_stateful_acl:
      user: foo
      host: http://localhost:8500
      mgmt_token: "{{ example_consul_server_config.acl_master_token }}"
      state: absent
    register: delete_consul_acl_task
    when: not ansible_check_mode

  - name: Ensure token was deleted
    uri:
      url: "http://localhost:8500/v1/acl/info/{{ delete_consul_acl_task.acl.token }}?token={{ example_consul_server_config.acl_master_token }}"
      return_content: yes
    register: confirm_delete_consul_acl_task
    when: not ansible_check_mode

  - assert:
      that:
        - delete_consul_acl_task | changed
        - confirm_delete_consul_acl_task.content == '[]'
    when: not ansible_check_mode

'''

import re
from urlparse import urlparse
from requests.exceptions import ConnectionError

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

try:
    import consul
    consul_prereq_installed=True
except ImportError:
    consul_prereq_installed=False

UUID_REGEXP = re.compile('[a-z0-9]{8}-(-?[a-z0-9]{4}){3}-[a-z0-9]{12}', re.I)
DEFAULT_TOKEN_POLICY='''key "" {
  policy = "read"
}
service "" {
  policy = "read"
}
'''

class ACLException(Exception):
    def __init__(self, message):
        self.message = message

class ACL():
    def __init__(self, name, **kwargs):
        # initialize class
        self.name = name
        self.policy = kwargs.get('policy') or DEFAULT_TOKEN_POLICY
        self.token = kwargs.get('token')
        self.changed = False

    def match(self, session):
        acls = session.acl.list()
        for acl in acls:
            if (acl.get('Name') == self.name):
                return acl

    def create(self, session, check_mode=False):
        if not check_mode:
            acl = session.acl.create(self.name, 'client', self.policy)
        else:
            acl = '<brand_new_token>'
        assert acl is not None, "Unable to create token!"
        self.token = acl
        self.changed = True
        return acl

    def update(self, session, force=False, check_mode=False, require_policy_match=True):
        acl = self.match(session)
        assert acl is not None, "Unable to update token!"
        if not force and acl.get('Rules') != self.policy:
            if require_policy_match:
                raise ACLException("Cannot update policy when force is not set!")
            else:
                self.policy = str(acl.get('Rules'))
        elif acl.get('Rules') != self.policy and force:
            self.changed = True
        self.token = acl.get('ID')
        if not check_mode:
            return session.acl.update(self.token, self.name, 'client', self.policy)
        else:
            return self.token

    def delete(self, session, check_mode=False):
        acl = self.match(session)
        assert acl is not None, "Unable to delete token!"
        self.token = acl.get('ID')
        self.policy = acl.get('Rules')
        self.changed = True
        if not check_mode:
            return session.acl.destroy(self.token)
        else:
            return self.token

def get_consul_session(uri, mgmt_token, verify_ssl=True):
    parsed_uri = urlparse(uri)

    scheme = parsed_uri.scheme
    host_cleanser = re.compile(':.*$')
    host = host_cleanser.sub('', parsed_uri.netloc)

    port_finder = re.compile(':(.*$)')
    port_inter = port_finder.search(parsed_uri.netloc)
    if port_inter is not None:
        port = port_inter.group(1)
    elif scheme == 'https':
        port = 443
    else:
        port = 80

    return consul.Consul(host=host,
                         port=port,
                         scheme=scheme,
                         verify=verify_ssl,
                         token=mgmt_token)

def execute(m):
    return_dict=dict(changed=False)
    check_mode = m.check_mode
    require_policy_match = m.params.get('require_policy_match')
    try:
        assert UUID_REGEXP.match(m.params.get('mgmt_token')) is not None,\
                "Passed token, %s, is not a valid token!" % m.params['mgmt_token']
    except AssertionError as e:
        m.fail_json(msg=e.message)
        # Ensure method exits here when it encounters a fatal error
        return None

    try:
        session = get_consul_session(m.params.get('host_uri'),
                                     m.params.get('mgmt_token'),
                                     m.params.get('verify_ssl'))

        acl = ACL(m.params.get('username'), policy=m.params.get('policy'))
        state = m.params.get('state')
        if state == 'present':
            try:
                acl.update(session, m.params.get('force_update'), check_mode=check_mode, require_policy_match=require_policy_match)
                msg = "ACL was successfully updated."
            except AssertionError:
                # update raised an AssertionError because no ACL was found, therefore we need to create it
                acl.create(session, check_mode=check_mode)
                msg = "ACL was successfully created."
        else:
            acl.delete(session, check_mode=check_mode)
            msg = "ACL was successfully deleted."

        return_dict = dict(msg=msg,changed=acl.changed, acl=dict(token=acl.token, policy=acl.policy, name=acl.name))
    except ConnectionError as e:
        m.fail_json(msg="Failed to connect to Consul. Got message: %s" % e.message)
    except ACLException as e:
        m.fail_json(msg=e.message)

    m.exit_json(**return_dict)

def main():
    # Define an ansible module
    module = AnsibleModule(
                argument_spec = dict(
                    username = dict(type='str',aliases=['user','name'],required=True),
                    host_uri = dict(type='str',aliases=['url','host'],default='https://consul.omadahealth.net'),
                    force_update = dict(type='bool',default=False,aliases=['update']),
                    mgmt_token = dict(type='str',required=True),
                    policy = dict(type='str',aliases=['rules']),
                    require_policy_match = dict(type='bool',default=True),
                    state = dict(type='str', choices=['present','absent'], default='present')
                    ),
                supports_check_mode = True
                )

    # Business logic
    execute(module)

## Module Boilerplate
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
