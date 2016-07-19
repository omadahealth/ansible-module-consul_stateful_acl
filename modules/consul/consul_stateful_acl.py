#!/usr/bin/env python2.7

# import some libraries
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
DEFAULT_TOKEN_POLICY='''
key "" {
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

    def create(self, session):
        acl = session.acl.create(self.name, 'client', self.policy)
        assert acl is not None, "Unable to create token!"
        self.token = acl
        self.changed = True
        return acl

    def update(self, session, force=False):
        acl = self.match(session)
        assert acl is not None, "Unable to update token!"
        if not force and acl.get('Rules') != self.policy:
            raise ACLException("Cannot update policy when force is not set!")
        elif acl.get('Rules') != self.policy and force:
            self.changed = True
        self.token = acl.get('ID')
        return session.acl.update(self.token, self.name, 'client', self.policy)

    def delete(self, session):
        acl = self.match(session)
        assert acl is not None, "Unable to delete token!"
        self.token = acl.get('ID')
        self.policy = acl.get('Rules')
        self.changed = True
        return session.acl.destroy(self.token)

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
                acl.update(session, m.params.get('force_update'))
                msg = "ACL was successfully updated."
            except AssertionError:
                # update raised an AssertionError because no ACL was found, therefore we need to create it
                acl.create(session)
                msg = "ACL was successfully created."
        else:
            acl.delete(session)
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
                    state = dict(type='str', choices=['present','absent'], default='present')
                    ),
                supports_check_mode = False
                )

    # Business logic
    execute(module)

## Module Boilerplate
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
