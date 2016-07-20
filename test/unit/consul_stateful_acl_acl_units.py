import unittest
import mock
import consul

import modules.consul.consul_stateful_acl as ConsulStatefulACL
from modules.consul.consul_stateful_acl import ACL
from modules.consul.consul_stateful_acl import ACLException

DEFAULT_TOKEN_POLICY='key "" {\n  policy = "read"\n}\nservice "" {\n  policy = "read"\n}\n'

class ConsulStatefulACLClassTestCase(unittest.TestCase):
    @mock.patch('consul.Consul')
    def setUp(self, mock_consul):
        self.consul = mock_consul
        attrs = {}
        self.consul.configure_mock(**attrs)
        self.instance = ACL('foo')

    def test_acl_match(self):
        '''
        Exercise ACL.match
        '''
        subject = self.instance.match(self.consul)
        self.consul.acl.list.assert_called_once()

    def test_acl_match_w_remote(self):
        '''
        Exercise ACL.match with a matching remote ACL

        assert test subject returns ACL which name matches
        '''
        remote_acls = [{'Name': 'foo', 'Rules': 'key "example/" {\n  policy = "read"\n}\nservice "example-" {\n  policy = "read"\n}\n', 'ModifyIndex': 101462, 'CreateIndex': 101462, 'Type': 'client', 'ID': 'BF30253D-22A9-4106-AA31-A6605CD6BA44'}]
        attrs = { 'acl.list.return_value': remote_acls }
        self.consul.configure_mock(**attrs)

        subject = self.instance.match(self.consul)
        self.assertEquals(subject, remote_acls[0])

    def test_acl_match_wo_remote(self):
        '''
        Exercise ACL.match with a matching remote ACL

        assert test subject returns ACL which name matches
        '''
        remote_acls = [{'Name': 'not_foo', 'Rules': 'key "example/" {\n  policy = "read"\n}\nservice "example-" {\n  policy = "read"\n}\n', 'ModifyIndex': 101462, 'CreateIndex': 101462, 'Type': 'client', 'ID': 'BF30253D-22A9-4106-AA31-A6605CD6BA44'}]
        attrs = { 'acl.list.return_value': remote_acls }
        self.consul.configure_mock(**attrs)

        subject = self.instance.match(self.consul)
        self.assertIsNone(subject)

    def test_acl_create(self):
        '''
        Exercise ACL.create
        '''
        attrs = { 'acl.create.return_value': 'BF30253D-22A9-4106-AA31-A6605CD6BA44' }
        self.consul.configure_mock(**attrs)

        subject = self.instance.create(self.consul)
        self.consul.acl.create.assert_called_once_with(self.instance.name,
                                                       'client',
                                                       DEFAULT_TOKEN_POLICY)

    def test_acl_update_w_remote(self):
        '''
        Exercise ACL.update with a matching remote
        '''
        known_token = 'BF30253D-22A9-4106-AA31-A6605CD6BA44'
        remote_acls = [{'Name': 'foo', 'Rules': 'key "example/" {\n  policy = "read"\n}\nservice "example-" {\n  policy = "read"\n}\n', 'ModifyIndex': 101462, 'CreateIndex': 101462, 'Type': 'client', 'ID': known_token}]
        attrs = { 'acl.list.return_value': remote_acls,
                  'acl.update.return_value': known_token }
        self.consul.configure_mock(**attrs)

        subject = self.instance.update(self.consul, True)
        self.assertEquals(subject, known_token)

    def test_acl_update_wo_remote(self):
        '''
        Exercise ACL.update without a matching remote
        '''
        attrs = { 'acl.list.return_value': [] }
        self.consul.configure_mock(**attrs)

        with self.assertRaises(AssertionError) as e:
            self.instance.update(self.consul)

        the_exception = e.exception
        self.assertEquals(the_exception.message, "Unable to update token!")

    def test_acl_update_exception(self):
        '''
        Exercise ACL.update with require_policy_match set to True

        Setup a case where a ACLException will be raised
        '''
        known_token = 'BF30253D-22A9-4106-AA31-A6605CD6BA44'
        remote_acls = [{'Name': 'foo', 'Rules': 'key "example/" {\n  policy = "read"\n}\nservice "example-" {\n  policy = "read"\n}\n', 'ModifyIndex': 101462, 'CreateIndex': 101462, 'Type': 'client', 'ID': known_token}]
        attrs = { 'acl.list.return_value': remote_acls,
                  'acl.update.return_value': known_token }
        self.consul.configure_mock(**attrs)

        with self.assertRaises(ACLException) as e:
            self.instance.update(self.consul, force=False, require_policy_match=True)

        the_exception = e.exception
        self.assertEquals(the_exception.message, "Cannot update policy when force is not set!")

    def test_acl_update_w_require_policy_match_set_False(self):
        '''
        Exercise ACL.update with require_policy_match set to False

        Handle with grace
        '''
        known_token = 'BF30253D-22A9-4106-AA31-A6605CD6BA44'
        remote_acls = [{'Name': 'foo', 'Rules': 'key "example/" {\n  policy = "read"\n}\nservice "example-" {\n  policy = "read"\n}\n', 'ModifyIndex': 101462, 'CreateIndex': 101462, 'Type': 'client', 'ID': known_token}]
        attrs = { 'acl.list.return_value': remote_acls,
                  'acl.update.return_value': known_token }
        self.consul.configure_mock(**attrs)

        subject = self.instance.update(self.consul, force=False, require_policy_match=False)

        self.assertEquals(subject, known_token)
        self.assertEquals(self.instance.policy, 'key "example/" {\n  policy = "read"\n}\nservice "example-" {\n  policy = "read"\n}\n')

    def test_acl_delete_w_remote(self):
        '''
        Exercise ACL.delete with a matching remote
        '''
        known_token = 'BF30253D-22A9-4106-AA31-A6605CD6BA44'
        remote_acls = [{'Name': 'foo', 'Rules': 'key "example/" {\n  policy = "read"\n}\nservice "example-" {\n  policy = "read"\n}\n', 'ModifyIndex': 101462, 'CreateIndex': 101462, 'Type': 'client', 'ID': known_token}]
        attrs = { 'acl.list.return_value': remote_acls,
                  'acl.destroy.return_value': known_token }
        self.consul.configure_mock(**attrs)

        subject = self.instance.delete(self.consul)
        self.assertEquals(subject, known_token)

    def test_acl_delete_wo_remote(self):
        '''
        Exercise ACL.delete without a matching remote
        '''
        attrs = { 'acl.list.return_value': [] }
        self.consul.configure_mock(**attrs)

        with self.assertRaises(AssertionError) as e:
            self.instance.delete(self.consul)

        the_exception = e.exception
        self.assertEquals(the_exception.message, "Unable to delete token!")
